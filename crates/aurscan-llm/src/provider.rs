use crate::config::ValidatedLlmConfig;
use crate::prompt::ProviderRequest;
use crate::types::TokenUsage;
use anyhow::{anyhow, bail, Context};
use serde::Deserialize;
use std::io::Read;

#[derive(Debug)]
pub(crate) struct ProviderResponse {
    pub(crate) content: String,
    pub(crate) finish_reason: String,
    pub(crate) usage: Option<TokenUsage>,
}

pub(crate) struct ApiKey(String);

pub(crate) fn load_api_key(config: &ValidatedLlmConfig) -> anyhow::Result<Option<ApiKey>> {
    let Some(variable) = config.api_key_env.as_deref() else {
        return Ok(None);
    };
    match std::env::var(variable) {
        Ok(value) if !value.is_empty() => Ok(Some(ApiKey(value))),
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            bail!("required API key environment variable {variable} is not set")
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("required API key environment variable {variable} is not valid Unicode")
        }
    }
}

pub(crate) trait ModelProvider: Send + Sync {
    fn send(
        &self,
        config: &ValidatedLlmConfig,
        request: &ProviderRequest,
        encoded_body: &[u8],
        api_key: Option<&ApiKey>,
    ) -> anyhow::Result<ProviderResponse>;
}

pub(crate) struct OpenAiCompatibleProvider {
    agent: ureq::Agent,
}

impl OpenAiCompatibleProvider {
    pub(crate) fn new(config: &ValidatedLlmConfig) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(config.timeout)
                .build(),
        }
    }
}

impl ModelProvider for OpenAiCompatibleProvider {
    fn send(
        &self,
        config: &ValidatedLlmConfig,
        request: &ProviderRequest,
        encoded_body: &[u8],
        api_key: Option<&ApiKey>,
    ) -> anyhow::Result<ProviderResponse> {
        if request.identity.model_id != config.model {
            bail!("LLM request identity does not match configured model");
        }
        let mut outgoing = self
            .agent
            .post(config.chat_completions_url.as_str())
            .set("Content-Type", "application/json");
        if let Some(api_key) = api_key {
            let authorization = format!("Bearer {}", api_key.0);
            outgoing = outgoing.set("Authorization", &authorization);
        }

        let response = match outgoing.send_bytes(encoded_body) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, _)) => {
                bail!("LLM provider returned HTTP status {status}")
            }
            Err(ureq::Error::Transport(error)) => {
                return Err(anyhow!(
                    "LLM provider transport failed ({:?})",
                    error.kind()
                ));
            }
        };
        let status = response.status();
        if !(200..300).contains(&status) {
            bail!("LLM provider returned HTTP status {status}");
        }
        let response_limit = config.max_request_bytes;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(response_limit as u64 + 1)
            .read_to_end(&mut bytes)
            .context("failed to read LLM provider response")?;
        if bytes.len() > response_limit {
            bail!("LLM provider response exceeds byte limit {response_limit}");
        }
        let response: ChatCompletionResponse = serde_json::from_slice(&bytes)
            .context("LLM provider returned an invalid response envelope")?;
        let choice = response
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("LLM provider response has no choices"))?;
        let choice: ChatChoice = serde_json::from_value(choice)
            .context("LLM provider returned an invalid first choice")?;
        let usage = response.usage.and_then(|usage| {
            Some(TokenUsage {
                input_tokens: usage.prompt_tokens?,
                output_tokens: usage.completion_tokens?,
            })
        });
        Ok(ProviderResponse {
            content: choice.message.content,
            finish_reason: choice.finish_reason,
            usage,
        })
    }
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<serde_json::Value>,
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
    finish_reason: String,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}
