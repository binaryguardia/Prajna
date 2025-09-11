import React, { useState, useEffect } from "react";

const ModelSelector = ({ authStatus, onModelSelect, onBack }) => {
	const [provider, setProvider] = useState("");
	const [models, setModels] = useState([]);
	const [selectedModel, setSelectedModel] = useState("");
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState("");

	useEffect(() => {
		// Pick first validated provider
		const validProvider = Object.keys(authStatus?.providers || {}).find(
			p => authStatus.providers[p].valid
		);
		setProvider(validProvider || "");
	}, [authStatus]);

	useEffect(() => {
		if (!provider) return;
		setLoading(true);
		fetch(`http://localhost:5000/api/auth/models/${provider}`)
			.then(res => res.json())
			.then(data => {
				setModels(data.models || []);
				setLoading(false);
			})
			.catch(() => {
				setError("Failed to fetch models");
				setLoading(false);
			});
	}, [provider]);

	const handleSelect = () => {
		if (!selectedModel) return;
		fetch("http://localhost:5000/api/auth/update-model", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ provider, model: selectedModel })
		})
			.then(res => res.json())
			.then(() => onModelSelect(selectedModel));
	};

	return (
		<div className="flex flex-col items-center justify-center h-screen bg-black text-green-400">
			<h2 className="text-2xl mb-6">Select Model for {provider}</h2>
			{loading && <div>Loading models...</div>}
			{error && <div className="text-red-400">{error}</div>}
			<select
				className="w-80 p-2 rounded bg-gray-800 text-green-400 border border-green-400 mb-4"
				value={selectedModel}
				onChange={e => setSelectedModel(e.target.value)}
			>
				<option value="">-- Select Model --</option>
				{models.map(m => (
					<option key={m} value={m}>{m}</option>
				))}
			</select>
			<button
				className="px-4 py-2 bg-green-700 rounded text-white"
				onClick={handleSelect}
				disabled={!selectedModel}
			>
				Continue to Chat
			</button>
			<button className="mt-4 px-4 py-2 bg-gray-700 rounded text-white" onClick={onBack}>Back</button>
		</div>
	);
};

export default ModelSelector;
