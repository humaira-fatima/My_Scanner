import React, { useState, useEffect } from 'react';

interface Target {
  id: number;
  domain_name: string;
  platform?: string;
}

interface Finding {
  id: number;
  target_id: number;
  title: string;
  severity: string;
  endpoint: string;
  draft_report: string;
  is_verified: boolean;
}

export default function App() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);
  const [newDomain, setNewDomain] = useState('');
  const [newPlatform, setNewPlatform] = useState('HackerOne');
  const [statusMessage, setStatusMessage] = useState('');
  const [activeTab, setActiveTab] = useState<'findings' | 'report'>('findings');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Session & Header State for BOLA & Logic Engine
  const [showSessionModal, setShowSessionModal] = useState(false);
  const [userAToken, setUserAToken] = useState('');
  const [userBToken, setUserBToken] = useState('');

  const API_BASE = 'https://miniature-dollop-97475g4r7rrvcxg4w-8000.app.github.dev/api';

  const fetchData = async () => {
    try {
      const targetRes = await fetch(`${API_BASE}/targets`);
      const targetData = await targetRes.json();
      setTargets(targetData);

      if (targetData.length > 0 && selectedTargetId === null) {
        setSelectedTargetId(targetData[0].id);
      }

      const findingRes = await fetch(`${API_BASE}/findings`);
      const findingData = await findingRes.json();
      setFindings(findingData);
    } catch (err) {
      console.error('Failed to fetch data from backend', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [selectedTargetId]);

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain) return;
    try {
      const res = await fetch(`${API_BASE}/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain_name: newDomain, platform: newPlatform }),
      });
      if (res.ok) {
        setNewDomain('');
        setNewPlatform('HackerOne');
        fetchData();
        setStatusMessage(`Target ${newDomain} added.`);
      }
    } catch (err) {
      setStatusMessage('Error adding target.');
    }
  };

  const handleDeleteTarget = async (targetId: number, domainName: string) => {
    if (!confirm(`Are you sure you want to delete ${domainName}? This will permanently clear its findings and scope.`)) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/targets/${targetId}`, {
        method: 'DELETE',
      });

      if (res.ok) {
        setTargets((prev) => prev.filter((t) => t.id !== targetId));
        setFindings((prev) => prev.filter((f) => f.target_id !== targetId));

        if (selectedTargetId === targetId) {
          const remainingTargets = targets.filter((t) => t.id !== targetId);
          setSelectedTargetId(remainingTargets.length > 0 ? remainingTargets[0].id : null);
        }
        setStatusMessage(`Target ${domainName} deleted successfully.`);
      } else {
        setStatusMessage(`Failed to delete target ${domainName}.`);
      }
    } catch (err) {
      setStatusMessage(`Error deleting target ${domainName}.`);
    }
  };

  const handleClearFindings = async () => {
    if (!selectedTargetId) return;
    try {
      const res = await fetch(`${API_BASE}/targets/${selectedTargetId}/findings`, {
        method: 'DELETE',
      });

      if (res.ok) {
        setFindings((prev) => prev.filter((f) => f.target_id !== selectedTargetId));
        setStatusMessage('All findings cleared for current target.');
      } else {
        setFindings((prev) => prev.filter((f) => f.target_id !== selectedTargetId));
        setStatusMessage('Cleared local findings view.');
      }
    } catch (err) {
      setFindings((prev) => prev.filter((f) => f.target_id !== selectedTargetId));
      setStatusMessage('Cleared local findings view.');
    }
  };

  // Push session tokens to backend
  const handleSaveSessions = async () => {
    if (!selectedTargetId) return;
    try {
      const res = await fetch(`${API_BASE}/targets/${selectedTargetId}/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auth_token_a: userAToken, auth_token_b: userBToken }),
      });
      if (res.ok) {
        setShowSessionModal(false);
        setStatusMessage('Session headers saved successfully.');
      } else {
        const errData = await res.json();
        setStatusMessage(errData.detail || 'Failed to save session headers.');
      }
    } catch (err) {
      setStatusMessage('Error saving session headers to backend.');
    }
  };

  // Generic scan trigger for Recon & Nuclei
  const handleTriggerScan = async (type: 'passive' | 'active') => {
    if (!selectedTargetId) return;
    const endpoint = type === 'passive' ? '/scan/trigger' : '/scan/active';
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: selectedTargetId }),
      });
      const data = await res.json();
      setStatusMessage(data.message || 'Scan queued.');
    } catch (err) {
      setStatusMessage(`Error queuing ${type} scan.`);
    }
  };

  // Custom Core Engine Triggers (JS Miner, DOM Scanner, Active XSS, XXE, BOLA, OWASP Logic)
  const handleEngineScan = async (
    engine: 'js_miner' | 'dom_scanner' | 'xss' | 'xxe' | 'bola' | 'owasp/logic'
  ) => {
    if (!selectedTargetId) return;
    try {
      const displayNames: Record<string, string> = {
        'owasp/logic': 'OWASP Logic',
        xss: 'Active XSS',
        xxe: 'XXE / XML Engine',
        js_miner: 'JS Miner',
        dom_scanner: 'DOM Scanner',
        bola: 'BOLA Engine',
      };

      const engineName = displayNames[engine] || engine.toUpperCase();
      setStatusMessage(`Initiating ${engineName} scan...`);

      const res = await fetch(`${API_BASE}/scan/${engine}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: selectedTargetId }),
      });

      const data = await res.json();

      if (!res.ok) {
        setStatusMessage(data.detail || `Error executing ${engineName} engine.`);
        return;
      }

      setStatusMessage(data.message || `${engineName} completed.`);
      fetchData();
    } catch (err) {
      setStatusMessage(`Error executing scan engine.`);
    }
  };

  const getSeverityBadge = (severity: string) => {
    const sev = severity.toLowerCase();
    const colors: Record<string, string> = {
      critical: 'bg-red-900 text-red-200 border-red-700',
      high: 'bg-orange-900 text-orange-200 border-orange-700',
      medium: 'bg-yellow-900 text-yellow-200 border-yellow-700',
      low: 'bg-blue-900 text-blue-200 border-blue-700',
    };
    return colors[sev] || 'bg-gray-800 text-gray-300 border-gray-700';
  };

  const getPlatformBadgeColor = (platform?: string) => {
    switch (platform) {
      case 'HackerOne': return 'bg-green-900 text-green-200 border-green-700';
      case 'Bugcrowd': return 'bg-orange-900 text-orange-200 border-orange-700';
      case 'Intigriti': return 'bg-purple-900 text-purple-200 border-purple-700';
      case 'Independent': return 'bg-blue-900 text-blue-200 border-blue-700';
      default: return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const filteredFindings = selectedTargetId
    ? findings.filter((f) => f.target_id === selectedTargetId)
    : findings;

  const currentTarget = targets.find((t) => t.id === selectedTargetId);

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Sidebar - Target Management */}
      <div className="w-80 bg-slate-900 border-r border-slate-800 flex flex-col p-4">
        <h1 className="text-xl font-bold text-indigo-400 mb-6 flex items-center gap-2">
          <span>🛡️</span> My_Scanner OSINT
        </h1>

        <form onSubmit={handleAddTarget} className="mb-6">
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Add Target Domain
          </label>
          <div className="flex flex-col gap-2">
            <input
              type="text"
              placeholder="example.com"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500"
            />
            <div className="flex gap-2">
              <select
                value={newPlatform}
                onChange={(e) => setNewPlatform(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-sm focus:outline-none focus:border-indigo-500 text-slate-300"
              >
                <option value="HackerOne">HackerOne</option>
                <option value="Bugcrowd">Bugcrowd</option>
                <option value="Intigriti">Intigriti</option>
                <option value="Independent">Independent</option>
              </select>
              <button
                type="submit"
                className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-1.5 rounded text-sm font-medium transition"
              >
                Add
              </button>
            </div>
          </div>
        </form>

        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
          Target Scope
        </h2>
        <div className="flex-1 overflow-y-auto space-y-2">
          {targets.map((t) => (
            <div
              key={t.id}
              className={`w-full text-left rounded transition flex flex-col border ${
                selectedTargetId === t.id
                  ? 'bg-indigo-950/60 border-indigo-800'
                  : 'bg-slate-800/20 border-transparent hover:bg-slate-800/50'
              }`}
            >
              <div className="w-full px-3 py-2 flex justify-between items-center">
                <button
                  onClick={() => setSelectedTargetId(t.id)}
                  className="flex-1 text-left flex justify-between items-center mr-2"
                >
                  <span className="font-medium text-slate-200">{t.domain_name}</span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded border ${getPlatformBadgeColor(
                      t.platform
                    )}`}
                  >
                    {t.platform || 'Unknown'}
                  </span>
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleDeleteTarget(t.id, t.domain_name);
                  }}
                  title="Delete Target"
                  className="text-slate-500 hover:text-red-400 p-1 text-xs transition"
                >
                  🗑️
                </button>
              </div>
              {selectedTargetId === t.id && (
                <div className="px-3 pb-2 flex justify-end">
                  <button
                    onClick={() => setShowSessionModal(true)}
                    className="text-[11px] text-indigo-400 hover:text-indigo-300 font-medium"
                  >
                    + Manage Sessions
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header Control Panel */}
        <div className="bg-slate-900 border-b border-slate-800 p-4 flex flex-wrap justify-between items-center gap-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-3">
              {currentTarget?.domain_name || 'Select Target'}
              {currentTarget && (
                <span className={`text-[11px] px-2 py-0.5 rounded border ${getPlatformBadgeColor(currentTarget.platform)}`}>
                  {currentTarget.platform}
                </span>
              )}
            </h2>
            {statusMessage && (
              <p className="text-xs text-indigo-400 mt-1">{statusMessage}</p>
            )}
          </div>

          {/* Engine Action Controls */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleTriggerScan('passive')}
              className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              ⚡ Passive Recon
            </button>
            <button
              onClick={() => handleEngineScan('js_miner')}
              className="bg-slate-800 hover:bg-slate-700 border border-indigo-900/60 text-indigo-300 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              🔍 JS Miner
            </button>
            <button
              onClick={() => handleEngineScan('dom_scanner')}
              className="bg-slate-800 hover:bg-slate-700 border border-purple-900/60 text-purple-300 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              🧪 DOM Scanner
            </button>
            <button
              onClick={() => handleEngineScan('xss')}
              className="bg-slate-800 hover:bg-slate-700 border border-rose-900/60 text-rose-300 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              💥 Active XSS
            </button>
            <button
              onClick={() => handleEngineScan('xxe')}
              className="bg-slate-800 hover:bg-slate-700 border border-yellow-900/60 text-yellow-300 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              ☣️ XXE / XML
            </button>
            <button
              onClick={() => handleEngineScan('bola')}
              className="bg-slate-800 hover:bg-slate-700 border border-amber-900/60 text-amber-300 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              🔑 BOLA Engine
            </button>
            <button
              onClick={() => handleEngineScan('owasp/logic')}
              className="bg-slate-800 hover:bg-slate-700 border border-teal-900/60 text-teal-300 px-3 py-1.5 rounded text-xs font-medium transition"
            >
              🧩 OWASP Logic
            </button>
            <button
              onClick={() => handleTriggerScan('active')}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded text-xs font-medium transition"
            >
              🎯 Nuclei Scan
            </button>
          </div>
        </div>

        {/* Dashboard Grid */}
        <div className="flex-1 p-6 overflow-y-auto bg-slate-950">
          <div className="mb-4 border-b border-slate-800 flex justify-between items-center pb-2">
            <button
              onClick={() => setActiveTab('findings')}
              className={`text-sm font-medium transition ${
                activeTab === 'findings'
                  ? 'border-b-2 border-indigo-500 text-indigo-400 pb-2'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Vulnerability Findings ({filteredFindings.length})
            </button>

            {filteredFindings.length > 0 && activeTab === 'findings' && (
              <button
                onClick={handleClearFindings}
                className="bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 text-xs px-3 py-1 rounded transition"
              >
                🗑️ Clear Findings
              </button>
            )}
          </div>

          {activeTab === 'findings' && (
            <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-900/50">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900 text-slate-400 text-xs uppercase">
                    <th className="p-3">Severity</th>
                    <th className="p-3">Vulnerability Title</th>
                    <th className="p-3">Endpoint / Resource</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-sm">
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="p-6 text-center text-slate-500">
                        No findings detected for this target yet.
                      </td>
                    </tr>
                  ) : (
                    filteredFindings.map((f) => (
                      <tr key={f.id} className="hover:bg-slate-800/30 transition">
                        <td className="p-3">
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getSeverityBadge(
                              f.severity
                            )}`}
                          >
                            {f.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="p-3 font-medium text-slate-200">{f.title}</td>
                        <td className="p-3 font-mono text-xs text-slate-400">{f.endpoint}</td>
                        <td className="p-3">
                          <button
                            onClick={() => {
                              setSelectedFinding(f);
                              setActiveTab('report');
                            }}
                            className="text-xs text-indigo-400 hover:underline"
                          >
                            View Report
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'report' && selectedFinding && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-4xl">
              <button
                onClick={() => setActiveTab('findings')}
                className="text-xs text-indigo-400 mb-4 inline-block hover:underline"
              >
                ← Back to Findings
              </button>
              <h3 className="text-xl font-bold text-slate-100 mb-2">{selectedFinding.title}</h3>
              <div className="mb-4 flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityBadge(
                    selectedFinding.severity
                  )}`}
                >
                  {selectedFinding.severity.toUpperCase()}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {selectedFinding.endpoint}
                </span>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded p-4 font-mono text-xs text-slate-300 whitespace-pre-wrap">
                {selectedFinding.draft_report}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Target Session Setup Modal */}
      {showSessionModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 w-full max-w-md shadow-xl"><h3 className="text-lg font-bold text-slate-100 mb-1">Target Session Setup</h3>
            <p className="text-xs text-slate-400 mb-4">Configure authorization headers and session tokens.</p>
            
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">User A Auth Token</label>
                <input 
                  type="text" 
                  value={userAToken}
                  onChange={(e) => setUserAToken(e.target.value)}
                  placeholder="Bearer token or session cookie..."
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500" 
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">User B Auth Token</label>
                <input 
                  type="text" 
                  value={userBToken}
                  onChange={(e) => setUserBToken(e.target.value)}
                  placeholder="Bearer token or session cookie..."
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500" 
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button 
                onClick={() => setShowSessionModal(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button 
                onClick={handleSaveSessions}
                className="px-4 py-2 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded shadow transition-colors"
              >
                Save Tokens
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}