const axios = require('axios');
const fs = require('fs');
const path = require('path');

const API_KEYS_FILE = path.join(__dirname, 'api_keys.json');

function initApiKeysFile() {
  if (!fs.existsSync(API_KEYS_FILE)) {
    fs.writeFileSync(API_KEYS_FILE, JSON.stringify({
      openai: { key: '', model: 'gpt-4o-mini', valid: false },
      gemini: { key: '', model: 'gemini-2.0-flash', valid: false },
      claude: { key: '', model: 'claude-3-5-sonnet', valid: false }
    }, null, 2));
  }
}

function getApiKeys() {
  try {
    return JSON.parse(fs.readFileSync(API_KEYS_FILE, 'utf8'));
  } catch (error) {
    return {
      openai: { key: '', model: 'gpt-4o-mini', valid: false },
      gemini: { key: '', model: 'gemini-2.0-flash', valid: false },
      claude: { key: '', model: 'claude-3-5-sonnet', valid: false }
    };
  }
}

function saveApiKeys(keys) {
  fs.writeFileSync(API_KEYS_FILE, JSON.stringify(keys, null, 2));
}

async function validateOpenAIKey(apiKey) {
  try {
    const exec = () => axios.get('https://api.openai.com/v1/models', {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      timeout: 10000
    });
    let lastErr;
    for (let i = 0; i < 3; i++) {
      try {
        const response = await exec();
        return response.status === 200;
      } catch (e) {
        lastErr = e;
        const status = e && (e.status || (e.response && e.response.status));
        const msg = (e && e.message) || '';
        if (!(status === 429 || /rate|quota/i.test(msg))) break;
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, i)));
      }
    }
    throw lastErr;
  } catch (error) {
    console.error('OpenAI validation error:', error.message);
    return false;
  }
}

async function validateGeminiKey(apiKey) {
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${apiKey}`;
    const body = { contents: [{ parts: [{ text: "Hello" }] }] };
    const exec = () => axios.post(url, body, { timeout: 10000 });
    let lastErr;
    for (let i = 0; i < 3; i++) {
      try {
        const response = await exec();
        return response.status === 200;
      } catch (e) {
        lastErr = e;
        const status = e && (e.status || (e.response && e.response.status));
        if (status !== 429) break;
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, i)));
      }
    }
    throw lastErr;
  } catch (error) {
    if (error.response) {
      console.error('Gemini validation error:', error.response.status, error.response.data);
    } else {
      console.error('Gemini validation error:', error.message);
    }
    return false;
  }
}

async function validateClaudeKey(apiKey) {
  try {
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: 'claude-3-5-sonnet-20240620',
        max_tokens: 100,
        messages: [{ role: 'user', content: 'Hello' }]
      },
      {
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        timeout: 10000
      }
    );
    return response.status === 200;
  } catch (error) {
    if (error.response) {
      console.error('Claude validation error:', error.response.status, error.response.data);
    } else {
      console.error('Claude validation error:', error.message);
    }
    return false;
  }
}

function getAvailableModels(provider) {
  const models = {
    openai: [
      'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4', 
      'gpt-3.5-turbo', 'gpt-3.5-turbo-16k'
    ],
    gemini: [
      'gemini-2.0-flash', 'gemini-2.0-flash-thinking', 'gemini-2.0-pro', 
      'gemini-1.5-pro', 'gemini-1.5-flash'
    ],
    claude: [
      'claude-3-5-sonnet', 'claude-3-opus', 'claude-3-sonnet', 
      'claude-3-haiku', 'claude-2.1'
    ]
  };
  return models[provider] || [];
}

module.exports = {
  initApiKeysFile,
  getApiKeys,
  saveApiKeys,
  validateOpenAIKey,
  validateGeminiKey,
  validateClaudeKey,
  getAvailableModels
};