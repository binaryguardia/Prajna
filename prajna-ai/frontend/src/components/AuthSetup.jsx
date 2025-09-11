import React, { useState } from "react";

const providers = [
	{ id: "openai", label: "OpenAI" },
	{ id: "gemini", label: "Gemini" },
	{ id: "claude", label: "Claude" }
];


const AuthSetup = ({ authStatus, onSuccess, onReset, pendingProvider }) => {
	const [apiKeys, setApiKeys] = useState({ openai: "", gemini: "", claude: "" });
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState("");
	const [validated, setValidated] = useState({ openai: false, gemini: false, claude: false });
	const [useTgpt, setUseTgpt] = useState(false);

	const handleInputChange = (provider, value) => {
		setApiKeys({ ...apiKeys, [provider]: value });
	};

	const handleValidate = async (provider) => {
		setLoading(true);
		setError("");
		try {
			const res = await fetch("http://localhost:5000/api/auth/validate", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ provider, apiKey: apiKeys[provider] })
			});
			const data = await res.json();
			if (data.valid) {
				setValidated({ ...validated, [provider]: true });
				onSuccess(provider); // Pass provider to App.js for correct navigation
			} else {
				setError(`Invalid API key for ${provider}`);
			}
		} catch (e) {
			setError("Validation failed. Try again.");
		}
		setLoading(false);
	};

		return (
			<div className="flex flex-col items-center justify-center h-screen bg-black text-green-400">
				<h2 className="text-2xl mb-6">Enter API Keys for LLM Providers</h2>
				{providers.map((p) => (
					<div key={p.id} className={`mb-4 w-80 ${pendingProvider && pendingProvider !== p.id ? 'opacity-40 pointer-events-none' : ''}`}>
						<label className="block mb-2">{p.label} API Key:</label>
						<input
							type="text"
							className="w-full p-2 rounded bg-gray-800 text-green-400 border border-green-400"
							value={apiKeys[p.id]}
							onChange={e => handleInputChange(p.id, e.target.value)}
							disabled={validated[p.id]}
						/>
						<button
							className="mt-2 px-4 py-1 bg-green-700 rounded text-white"
							onClick={() => handleValidate(p.id)}
							disabled={loading || validated[p.id] || !apiKeys[p.id]}
						>
							{validated[p.id] ? "Validated" : "Validate"}
						</button>
					</div>
				))}
				<div className="mt-8 mb-4 w-80">
					<button className="w-full px-4 py-2 bg-blue-700 rounded text-white text-lg" onClick={() => { setUseTgpt(true); onSuccess('tgpt'); }}>
						Use tgpt (Free, requires local install)
					</button>
					<div className="text-xs text-gray-400 mt-2">No API key required. You must have tgpt installed on your system.</div>
				</div>
				{error && <div className="text-red-400 mt-2">{error}</div>}
				<button className="mt-6 px-4 py-2 bg-gray-700 rounded text-white" onClick={() => onReset()}>Reset All</button>
			</div>
		);
};

export default AuthSetup;
