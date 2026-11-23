import React from 'react';

interface NeuralCoreOrbProps {
  emergencyStop: boolean;
  isStreaming?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const NeuralCoreOrb: React.FC<NeuralCoreOrbProps> = ({
  emergencyStop,
  isStreaming = false,
  size = 'md',
}) => {
  const dims =
    size === 'lg' ? 'w-44 h-44' : size === 'sm' ? 'w-11 h-11' : 'w-32 h-32';

  const primaryStroke = emergencyStop
    ? '#ef4444'
    : isStreaming
      ? '#60a5fa'
      : '#3b82f6';
  const accentStroke = emergencyStop ? '#991b1b' : '#dc2626';

  return (
    <div
      className={`relative ${dims} flex items-center justify-center select-none shrink-0`}
      aria-hidden="true"
    >
      <div
        className={`absolute inset-2 rounded-full blur-2xl transition-opacity duration-300 ${
          emergencyStop
            ? 'bg-red-600/25 opacity-95'
            : isStreaming
              ? 'bg-blue-500/30 opacity-100'
              : 'bg-blue-600/20 opacity-75'
        }`}
      />
      <svg
        viewBox="0 0 200 200"
        className="w-full h-full relative z-10 overflow-visible"
      >
        <defs>
          <radialGradient id="godCoreCenterGrad" cx="50%" cy="50%" r="50%">
            <stop
              offset="0%"
              stopColor={emergencyStop ? '#fca5a5' : '#93c5fd'}
              stopOpacity="0.95"
            />
            <stop
              offset="45%"
              stopColor={primaryStroke}
              stopOpacity="0.45"
            />
            <stop offset="100%" stopColor="#090b10" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Outer calibration ring */}
        <circle
          cx="100"
          cy="100"
          r="90"
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="1"
        />

        {/* Clockwise primary neural ring */}
        <g className={emergencyStop ? '' : 'neural-orbit-cw'}>
          <circle
            cx="100"
            cy="100"
            r="76"
            fill="none"
            stroke={primaryStroke}
            strokeWidth="1.5"
            strokeDasharray="68 28 18 28"
            strokeLinecap="round"
            opacity="0.85"
          />
          <circle cx="176" cy="100" r="3" fill={primaryStroke} />
          <circle cx="24" cy="100" r="2.5" fill={accentStroke} />
        </g>

        {/* Counter-clockwise crimson/sapphire dual ring */}
        <g className={emergencyStop ? '' : 'neural-orbit-ccw'}>
          <circle
            cx="100"
            cy="100"
            r="56"
            fill="none"
            stroke={accentStroke}
            strokeWidth="1.25"
            strokeDasharray="36 44"
            strokeLinecap="round"
            opacity="0.75"
          />
          <polygon
            points="100,34 104,42 96,42"
            fill={primaryStroke}
            opacity="0.85"
          />
        </g>

        {/* Inner geometric lattice */}
        <circle
          cx="100"
          cy="100"
          r="38"
          fill="url(#godCoreCenterGrad)"
          stroke="rgba(255,255,255,0.14)"
          strokeWidth="1"
        />
        <circle
          cx="100"
          cy="100"
          r="12"
          fill={emergencyStop ? '#ef4444' : '#3b82f6'}
          opacity="0.9"
        />
        <circle cx="100" cy="100" r="4.5" fill="#f8fafc" />
      </svg>
    </div>
  );
};
