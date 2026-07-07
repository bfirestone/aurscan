// Wired into the CLI surface by a later task in this epic; the public API
// here is exercised only by this module's tests until then.
#![allow(dead_code)]

use aurscan_core::AurMetadata;
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Deserialize)]
pub struct AurInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Depends", default)]
    pub depends: Vec<String>,
    #[serde(rename = "MakeDepends", default)]
    pub make_depends: Vec<String>,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "FirstSubmitted")]
    pub first_submitted: i64,
    #[serde(rename = "LastModified")]
    pub last_modified: i64,
    #[serde(rename = "OutOfDate")]
    pub out_of_date: Option<i64>,
    #[serde(rename = "Popularity")]
    pub popularity: f64,
    #[serde(rename = "NumVotes")]
    pub num_votes: u32,
}

impl AurInfo {
    pub fn to_metadata(&self) -> AurMetadata {
        AurMetadata {
            maintainer: self.maintainer.clone(),
            first_submitted: self.first_submitted,
            last_modified: self.last_modified,
            out_of_date: self.out_of_date,
            popularity: self.popularity,
            num_votes: self.num_votes,
        }
    }
}

#[derive(Deserialize)]
struct RpcResponse {
    results: Vec<AurInfo>,
}

const RPC_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
const CHUNK_SIZE: usize = 150;

/// Batched POST of `arg[]` params against the AUR RPC v5 info endpoint,
/// chunked so a large dependency set never exceeds the server's arg limit.
fn fetch(names: &[&str]) -> anyhow::Result<Vec<AurInfo>> {
    let mut all = Vec::new();
    for chunk in names.chunks(CHUNK_SIZE) {
        let pairs: Vec<(&str, &str)> = chunk.iter().map(|n| ("arg[]", *n)).collect();
        let resp: RpcResponse = ureq::post(RPC_URL).send_form(&pairs)?.into_json()?;
        all.extend(resp.results);
    }
    Ok(all)
}

/// Look up AUR metadata for a set of package names, keyed by package name.
/// Packages that don't exist in the AUR (e.g. repo packages) are simply
/// absent from the returned map.
pub fn info(names: &[&str]) -> anyhow::Result<HashMap<String, AurInfo>> {
    info_with(names, fetch)
}

fn info_with(
    names: &[&str],
    fetch_fn: impl Fn(&[&str]) -> anyhow::Result<Vec<AurInfo>>,
) -> anyhow::Result<HashMap<String, AurInfo>> {
    let infos = fetch_fn(names)?;
    Ok(infos.into_iter().map(|i| (i.name.clone(), i)).collect())
}

/// Strip a version constraint (`>=`, `=`, `<`, ...) off a dependency spec,
/// leaving just the bare package name.
pub fn strip_ver(dep: &str) -> &str {
    dep.split(['>', '=', '<']).next().unwrap_or(dep)
}

/// BFS over `depends` + `make_depends`, resolving only the dependencies the
/// AUR RPC actually knows about (repo packages return nothing and are
/// dropped). Cycle-safe via a visited set.
pub fn resolve_aur_deps(roots: &[&str]) -> anyhow::Result<Vec<AurInfo>> {
    resolve_aur_deps_with(roots, fetch)
}

fn resolve_aur_deps_with(
    roots: &[&str],
    fetch_fn: impl Fn(&[&str]) -> anyhow::Result<Vec<AurInfo>>,
) -> anyhow::Result<Vec<AurInfo>> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for &root in roots {
        if visited.insert(root.to_string()) {
            queue.push_back(root.to_string());
        }
    }

    let mut result = Vec::new();
    while !queue.is_empty() {
        let batch: Vec<String> = queue.drain(..).collect();
        let refs: Vec<&str> = batch.iter().map(String::as_str).collect();
        let infos = fetch_fn(&refs)?;

        for info in &infos {
            for dep in info.depends.iter().chain(info.make_depends.iter()) {
                let stripped = strip_ver(dep).to_string();
                if visited.insert(stripped.clone()) {
                    queue.push_back(stripped);
                }
            }
        }
        result.extend(infos);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info(name: &str, depends: Vec<&str>) -> AurInfo {
        AurInfo {
            name: name.to_string(),
            package_base: name.to_string(),
            version: "1.0-1".to_string(),
            depends: depends.into_iter().map(String::from).collect(),
            make_depends: Vec::new(),
            maintainer: Some("m".to_string()),
            first_submitted: 0,
            last_modified: 0,
            out_of_date: None,
            popularity: 0.0,
            num_votes: 0,
        }
    }

    #[test]
    fn to_metadata_maps_the_shared_subset_of_fields() {
        let info = AurInfo {
            name: "a".to_string(),
            package_base: "a".to_string(),
            version: "1.0-1".to_string(),
            depends: vec![],
            make_depends: vec![],
            maintainer: Some("m".to_string()),
            first_submitted: 100,
            last_modified: 200,
            out_of_date: Some(300),
            popularity: 1.5,
            num_votes: 7,
        };
        let meta = info.to_metadata();
        assert_eq!(meta.maintainer, Some("m".to_string()));
        assert_eq!(meta.first_submitted, 100);
        assert_eq!(meta.last_modified, 200);
        assert_eq!(meta.out_of_date, Some(300));
        assert_eq!(meta.popularity, 1.5);
        assert_eq!(meta.num_votes, 7);
    }

    #[test]
    fn strip_ver_removes_version_constraints() {
        assert_eq!(strip_ver("foo>=1.0"), "foo");
        assert_eq!(strip_ver("foo=1.0"), "foo");
        assert_eq!(strip_ver("foo<2.0"), "foo");
        assert_eq!(strip_ver("foo"), "foo");
    }

    #[test]
    fn info_with_builds_map_keyed_by_name() {
        let fixture = |_: &[&str]| -> anyhow::Result<Vec<AurInfo>> {
            Ok(vec![sample_info("a", vec![]), sample_info("b", vec![])])
        };
        let map = info_with(&["a", "b"], fixture).unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("a"));
        assert!(map.contains_key("b"));
    }

    #[test]
    fn resolve_aur_deps_bfs_stops_at_repo_packages() {
        // a depends on b (AUR) and c (repo package -> not returned by AUR RPC)
        let fetch_fn = |names: &[&str]| -> anyhow::Result<Vec<AurInfo>> {
            let mut out = Vec::new();
            for &n in names {
                match n {
                    "a" => out.push(sample_info("a", vec!["b", "c"])),
                    "b" => out.push(sample_info("b", vec![])),
                    _ => {} // "c" is a repo package, AUR RPC returns nothing
                }
            }
            Ok(out)
        };

        let result = resolve_aur_deps_with(&["a"], fetch_fn).unwrap();
        let names: Vec<&str> = result.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn resolve_aur_deps_strips_version_constraints_before_lookup() {
        let fetch_fn = |names: &[&str]| -> anyhow::Result<Vec<AurInfo>> {
            let mut out = Vec::new();
            for &n in names {
                match n {
                    "a" => out.push(sample_info("a", vec!["b>=1.0"])),
                    "b" => out.push(sample_info("b", vec![])),
                    _ => {}
                }
            }
            Ok(out)
        };

        let result = resolve_aur_deps_with(&["a"], fetch_fn).unwrap();
        let names: Vec<&str> = result.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn resolve_aur_deps_is_cycle_safe() {
        // a depends on b, b depends back on a
        let fetch_fn = |names: &[&str]| -> anyhow::Result<Vec<AurInfo>> {
            let mut out = Vec::new();
            for &n in names {
                match n {
                    "a" => out.push(sample_info("a", vec!["b"])),
                    "b" => out.push(sample_info("b", vec!["a"])),
                    _ => {}
                }
            }
            Ok(out)
        };

        let result = resolve_aur_deps_with(&["a"], fetch_fn).unwrap();
        let names: Vec<&str> = result.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
