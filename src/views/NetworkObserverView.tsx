import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import { NetworkTopologySvg } from '../components/NetworkTopologySvg';
import { SENSOR_NODE_SPECS } from '../shared/ginAnalytics';
import type { NetworkAssetRecord, NetworkAssetType } from '../shared/ginTypes';

export const NetworkObserverView: React.FC = () => {
  const { setActiveSection } = useGodWorkspace();
  const {
    networkAssets,
    addNetworkAsset,
    ingestAssetTelemetry,
    toggleIsolateAsset,
    deleteNetworkAsset,
    runBehaviourAnalysis,
    isAnalyzingBehaviour,
  } = useGinIntelligence();

  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(
    networkAssets[0]?.id || null
  );
  const [hostname, setHostname] = useState('');
  const [ipRange, setIpRange] = useState('');
  const [authorizedScope, setAuthorizedScope] = useState('Lab-Authorized-VLAN10');
  const [assetType, setAssetType] = useState<NetworkAssetType>('sensor');
  const [dnsQueriesPerMin, setDnsQueriesPerMin] = useState('48');
  const [nxdomainPercent, setNxdomainPercent] = useState('4');
  const [outboundMbps, setOutboundMbps] = useState('18');
  const [baselineMbps, setBaselineMbps] = useState('20');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const selectedAsset: NetworkAssetRecord | null =
    networkAssets.find((a) => a.id === selectedAssetId) || networkAssets[0] || null;

  const nominalCount = networkAssets.filter((a) => a.status === 'nominal').length;
  const anomalousCount = networkAssets.filter((a) => a.status === 'anomalous').length;
  const degradedCount = networkAssets.filter((a) => a.status === 'degraded').length;
  const totalDnsQpm = networkAssets.reduce((sum, a) => sum + a.dnsQueriesPerMin, 0);
  const totalOutboundMbps = networkAssets.reduce((sum, a) => sum + a.outboundMbps, 0);

  const handleRegisterAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      const res = await addNetworkAsset({
        hostname,
        ipRange,
        authorizedScope,
        assetType,
        dnsQueriesPerMin: Number(dnsQueriesPerMin) || 0,
        nxdomainRatio: (Number(nxdomainPercent) || 0) / 100,
        outboundMbps: Number(outboundMbps) || 0,
        baselineMbps: Number(baselineMbps) || 1,
      });
      if (!res.ok) {
        setFormError(res.error || 'Invalid authorized asset parameters.');
      } else {
        setHostname('');
        setIpRange('');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleSimulateDriftSample = async (asset: NetworkAssetRecord) => {
    // Ingests an elevated passive telemetry sample to verify live anomaly scoring
    await ingestAssetTelemetry(asset.id, {
      dnsQueriesPerMin: asset.status === 'anomalous' ? 35 : 225,
      nxdomainRatio: asset.status === 'anomalous' ? 0.03 : 0.31,
      outboundMbps:
        asset.status === 'anomalous'
          ? Math.max(5, Number((asset.baselineMbps * 0.9).toFixed(1)))
          : Number((asset.baselineMbps * 3.1).toFixed(1)),
      baselineMbps: asset.baselineMbps,
    });
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
            <Activity className="w-3.5 h-3.5" />
            <span>GIN v0.2 Operational · Passive Metadata Ingestion (Zero Packet Interception)</span>
          </div>
          <h1 className="text-2xl font-bold text-white">GOD Network Observer</h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Monitor explicitly authorized network assets via aggregated DNS metadata, NetFlow
            bandwidth drift, and OSINT threat correlation. Covert TLS decryption and credential
            capture are strictly disabled by architecture.
          </p>
        </div>

        <button
          type="button"
          disabled={isAnalyzingBehaviour}
          onClick={async () => {
            await runBehaviourAnalysis();
            setActiveSection('behaviour');
          }}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzingBehaviour ? 'animate-spin' : ''}`} />
          <span>Run Behaviour Analysis</span>
        </button>
      </div>

      {/* Telemetry Summary Strip */}
      <section
        aria-label="Network observer metrics"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1">
          <p className="text-xs text-slate-400">Authorized Assets</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums">
            {networkAssets.length}
          </p>
          <p className="text-xs text-slate-500 tabular-nums">
            {nominalCount} nominal · {degradedCount} degraded
          </p>
        </div>

        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1">
          <p className="text-xs text-slate-400">Active Anomaly Alerts</p>
          <p
            className={`text-2xl font-bold font-mono tabular-nums ${
              anomalousCount > 0 ? 'text-red-400' : 'text-emerald-400'
            }`}
          >
            {anomalousCount}
          </p>
          <p className="text-xs text-slate-500">Threshold: anomaly score ≥ 65/100</p>
        </div>

        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1">
          <p className="text-xs text-slate-400">Aggregate DNS Metadata</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums">
            {totalDnsQpm.toLocaleString()}{' '}
            <span className="text-xs font-normal text-slate-400">q/min</span>
          </p>
          <p className="text-xs text-slate-500">Query counts & NXDOMAIN ratios only</p>
        </div>

        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1">
          <p className="text-xs text-slate-400">Observed Flow Volume</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums">
            {totalOutboundMbps.toFixed(1)}{' '}
            <span className="text-xs font-normal text-slate-400">Mbps</span>
          </p>
          <p className="text-xs text-slate-500">NetFlow / IPFIX egress summaries</p>
        </div>
      </section>

      {/* Interactive Network Topology + Selected Asset Inspector */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-8 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Authorized Network Topology</h2>
            <span className="text-xs font-mono text-slate-400">
              Click any node to inspect telemetry
            </span>
          </div>
          <NetworkTopologySvg
            assets={networkAssets}
            selectedAssetId={selectedAsset?.id || null}
            onSelectAsset={(asset) => setSelectedAssetId(asset.id)}
          />
        </div>

        <div className="lg:col-span-4 rounded-xl bg-[#0f131c] border border-white/[0.08] p-5 space-y-4">
          <h2 className="text-base font-semibold text-white">Selected Asset Telemetry</h2>
          {!selectedAsset ? (
            <p className="text-sm text-slate-400">
              Register an authorized asset below to inspect DNS and flow telemetry.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1">
                <p className="text-sm font-mono font-semibold text-white truncate">
                  {selectedAsset.hostname}
                </p>
                <p className="text-xs font-mono text-slate-400 tabular-nums">
                  {selectedAsset.ipRange} · {selectedAsset.authorizedScope}
                </p>
                <p
                  className={`text-xs font-mono font-semibold ${
                    selectedAsset.status === 'anomalous'
                      ? 'text-red-400'
                      : selectedAsset.status === 'degraded'
                        ? 'text-amber-300'
                        : selectedAsset.status === 'isolated'
                          ? 'text-slate-300'
                          : 'text-emerald-400'
                  }`}
                >
                  Status: {selectedAsset.status.toUpperCase()} · Score:{' '}
                  {selectedAsset.anomalyScore}/100
                </p>
              </div>

              <dl className="divide-y divide-white/[0.06] border-y border-white/[0.06] text-xs font-mono tabular-nums">
                <div className="py-2 flex justify-between">
                  <dt className="text-slate-400">Asset Class</dt>
                  <dd className="text-slate-200">{selectedAsset.assetType}</dd>
                </div>
                <div className="py-2 flex justify-between">
                  <dt className="text-slate-400">DNS Metadata Rate</dt>
                  <dd className="text-slate-200">{selectedAsset.dnsQueriesPerMin} q/min</dd>
                </div>
                <div className="py-2 flex justify-between">
                  <dt className="text-slate-400">NXDOMAIN Ratio</dt>
                  <dd className="text-slate-200">
                    {(selectedAsset.nxdomainRatio * 100).toFixed(1)}%
                  </dd>
                </div>
                <div className="py-2 flex justify-between">
                  <dt className="text-slate-400">Outbound / Baseline</dt>
                  <dd className="text-slate-200">
                    {selectedAsset.outboundMbps.toFixed(1)} / {selectedAsset.baselineMbps.toFixed(1)}{' '}
                    Mbps
                  </dd>
                </div>
              </dl>

              <div className="space-y-1">
                <p className="text-xs font-medium text-slate-300">Threat Correlation</p>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {selectedAsset.threatMatch}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => handleSimulateDriftSample(selectedAsset)}
                  className="px-3 py-1.5 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.12] text-slate-100 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {selectedAsset.status === 'anomalous'
                    ? 'Ingest Baseline Recovery'
                    : 'Ingest Anomaly Sample'}
                </button>
                <button
                  type="button"
                  onClick={() => toggleIsolateAsset(selectedAsset.id)}
                  className="px-3 py-1.5 text-xs font-medium bg-red-950/40 hover:bg-red-950/70 border border-red-500/30 text-red-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {selectedAsset.status === 'isolated' ? 'Clear Isolation' : 'Flag Isolated'}
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Authorized Asset Registration & Telemetry Ingestion Form */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
        <div>
          <h2 className="text-base font-semibold text-white">
            Ingest Authorized Network Asset & Passive Telemetry
          </h2>
          <p className="text-xs text-slate-400">
            Declare an explicit authorized scope label and ingest passive DNS/flow metrics for
            real-time anomaly scoring.
          </p>
        </div>

        <form onSubmit={handleRegisterAsset} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="space-y-1">
              <label htmlFor="net-hostname" className="block text-xs text-slate-300">
                Hostname
              </label>
              <input
                id="net-hostname"
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="e.g., sensor-edge-05.lab"
                maxLength={120}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="net-ip" className="block text-xs text-slate-300">
                IP / CIDR Range
              </label>
              <input
                id="net-ip"
                type="text"
                value={ipRange}
                onChange={(e) => setIpRange(e.target.value)}
                placeholder="e.g., 10.42.10.55/32"
                maxLength={64}
                className="w-full px-3 py-2 text-xs font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="net-scope" className="block text-xs text-slate-300">
                Authorized Scope
              </label>
              <input
                id="net-scope"
                type="text"
                value={authorizedScope}
                onChange={(e) => setAuthorizedScope(e.target.value)}
                placeholder="Lab-Authorized-VLAN10"
                maxLength={120}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="net-type" className="block text-xs text-slate-300">
                Asset Type
              </label>
              <select
                id="net-type"
                value={assetType}
                onChange={(e) => setAssetType(e.target.value as NetworkAssetType)}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="sensor">Passive Sensor</option>
                <option value="gateway">Gateway</option>
                <option value="server">Server</option>
                <option value="workstation">Workstation</option>
                <option value="windows_node">Windows Node (Spec)</option>
                <option value="kali_node">Kali Node (Spec)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="space-y-1">
              <label htmlFor="net-dns" className="block text-xs text-slate-300">
                DNS Rate (q/min)
              </label>
              <input
                id="net-dns"
                type="number"
                min={0}
                max={1000000}
                value={dnsQueriesPerMin}
                onChange={(e) => setDnsQueriesPerMin(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#090b10] border border-white/[0.1] rounded-lg text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="net-nxdomain" className="block text-xs text-slate-300">
                NXDOMAIN (%)
              </label>
              <input
                id="net-nxdomain"
                type="number"
                min={0}
                max={100}
                step="0.5"
                value={nxdomainPercent}
                onChange={(e) => setNxdomainPercent(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#090b10] border border-white/[0.1] rounded-lg text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="net-outbound" className="block text-xs text-slate-300">
                Outbound Flow (Mbps)
              </label>
              <input
                id="net-outbound"
                type="number"
                min={0}
                max={100000}
                step="0.1"
                value={outboundMbps}
                onChange={(e) => setOutboundMbps(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#090b10] border border-white/[0.1] rounded-lg text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="net-baseline" className="block text-xs text-slate-300">
                Baseline Flow (Mbps)
              </label>
              <input
                id="net-baseline"
                type="number"
                min={0.5}
                max={100000}
                step="0.1"
                value={baselineMbps}
                onChange={(e) => setBaselineMbps(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#090b10] border border-white/[0.1] rounded-lg text-white focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {formError && (
            <div
              role="alert"
              className="flex items-start gap-2 text-xs text-red-300 bg-red-950/30 border border-red-500/30 rounded-lg px-3 py-2"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
              <span>{formError}</span>
            </div>
          )}

          <div className="flex items-center justify-between gap-4 pt-1">
            <span className="text-xs font-mono text-slate-500">
              Governance: Direct LAN probing and covert TLS interception are rejected.
            </span>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Register Asset Telemetry</span>
            </button>
          </div>
        </form>
      </section>

      {/* Authorized Inventory Data Table */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] overflow-hidden">
        <div className="px-6 py-4 border-b border-white/[0.07] flex items-center justify-between gap-4">
          <h2 className="text-base font-semibold text-white">Authorized Network Asset Inventory</h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {networkAssets.length} registered
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/[0.07] bg-[#0b0e15] text-xs font-semibold text-slate-400">
                <th className="py-2.5 px-5">Hostname & Scope</th>
                <th className="py-2.5 px-4">IP / Class</th>
                <th className="py-2.5 px-4 text-right">DNS q/min</th>
                <th className="py-2.5 px-4 text-right">NXDOMAIN</th>
                <th className="py-2.5 px-4 text-right">Flow (Mbps)</th>
                <th className="py-2.5 px-4 text-right">Anomaly</th>
                <th className="py-2.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.05] text-xs">
              {networkAssets.map((asset) => (
                <tr
                  key={asset.id}
                  className={`hover:bg-white/[0.02] ${
                    selectedAsset?.id === asset.id ? 'bg-blue-950/15' : ''
                  }`}
                >
                  <td className="py-3 px-5">
                    <button
                      type="button"
                      onClick={() => setSelectedAssetId(asset.id)}
                      className="text-left font-mono font-semibold text-slate-100 hover:text-blue-400 cursor-pointer"
                    >
                      {asset.hostname}
                    </button>
                    <p className="text-[11px] text-slate-500">{asset.authorizedScope}</p>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                    {asset.ipRange} · <span className="text-slate-500">{asset.assetType}</span>
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-slate-200 tabular-nums">
                    {asset.dnsQueriesPerMin}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-slate-200 tabular-nums">
                    {(asset.nxdomainRatio * 100).toFixed(1)}%
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-slate-200 tabular-nums whitespace-nowrap">
                    {asset.outboundMbps.toFixed(1)} / {asset.baselineMbps.toFixed(1)}
                  </td>
                  <td className="py-3 px-4 text-right font-mono tabular-nums whitespace-nowrap">
                    <span
                      className={
                        asset.status === 'anomalous'
                          ? 'text-red-400 font-semibold'
                          : asset.status === 'degraded'
                            ? 'text-amber-300 font-semibold'
                            : asset.status === 'isolated'
                              ? 'text-slate-400'
                              : 'text-emerald-400'
                      }
                    >
                      {asset.anomalyScore}/100 ({asset.status})
                    </span>
                  </td>
                  <td className="py-3 px-5 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => deleteNetworkAsset(asset.id)}
                      aria-label={`Delete network asset ${asset.hostname}`}
                      className="p-1.5 text-slate-400 hover:text-red-400 rounded-md cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Modular Sensor & Local Windows/Kali Node Interfaces */}
      <section className="space-y-4">
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-white">
            Modular Sensor & Outbound Local Node Interfaces
          </h2>
          <p className="text-xs text-slate-400">
            Remote Windows and Kali Linux nodes connect strictly via authenticated outbound TLS 1.3
            relays—never inbound scanning from Cloud Run.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {SENSOR_NODE_SPECS.map((spec) => (
            <article
              key={spec.id}
              className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-5 space-y-3"
            >
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-semibold text-white">{spec.platform}</h3>
                <span
                  className={`text-[11px] font-mono ${
                    spec.enrollmentStatus === 'active_cloud_ingestion'
                      ? 'text-emerald-400'
                      : 'text-slate-400'
                  }`}
                >
                  {spec.enrollmentStatus === 'active_cloud_ingestion'
                    ? 'Active v0.2'
                    : 'Unpaired Spec'}
                </span>
              </div>

              <p className="text-xs font-mono text-blue-300 leading-relaxed">{spec.transport}</p>
              <p className="text-xs text-slate-400">{spec.authMechanism}</p>

              <div className="pt-2 border-t border-white/[0.06] space-y-1">
                <p className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Permitted Passive Metadata</span>
                </p>
                <ul className="text-xs text-slate-400 space-y-0.5">
                  {spec.permittedTelemetry.map((item) => (
                    <li key={item}>· {item}</li>
                  ))}
                </ul>
              </div>

              <div className="pt-2 border-t border-white/[0.06] space-y-1">
                <p className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                  <span>Hard Prohibited Boundaries</span>
                </p>
                <ul className="text-xs text-slate-500 space-y-0.5">
                  {spec.prohibitedCapabilities.map((item) => (
                    <li key={item}>· {item}</li>
                  ))}
                </ul>
              </div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
};
