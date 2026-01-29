import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

function EventTimeline({ data }) {
  if (!data || Object.keys(data).length === 0) {
    return <div style={{ textAlign: 'center', color: '#8b949e' }}>Loading timeline...</div>;
  }

  // Transform data for Recharts
  const chartData = Object.entries(data).map(([timestamp, severities]) => {
    const date = new Date(timestamp);
    return {
      time: date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      CRITICAL: severities.CRITICAL || 0,
      HIGH: severities.HIGH || 0,
      MEDIUM: severities.MEDIUM || 0,
      LOW: severities.LOW || 0
    };
  });

  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={chartData}>
        <defs>
          <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ff0000" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#ff0000" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ff6600" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#ff6600" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ffaa00" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#ffaa00" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00ff7f" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#00ff7f" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#2a3f5f" />
        <XAxis dataKey="time" stroke="#8b949e" />
        <YAxis stroke="#8b949e" />
        <Tooltip 
          contentStyle={{ 
            background: '#1e2640', 
            border: '1px solid #2a3f5f',
            borderRadius: '8px'
          }}
        />
        <Legend />
        <Area 
          type="monotone" 
          dataKey="CRITICAL" 
          stackId="1"
          stroke="#ff0000" 
          fillOpacity={1}
          fill="url(#colorCritical)" 
        />
        <Area 
          type="monotone" 
          dataKey="HIGH" 
          stackId="1"
          stroke="#ff6600" 
          fillOpacity={1}
          fill="url(#colorHigh)" 
        />
        <Area 
          type="monotone" 
          dataKey="MEDIUM" 
          stackId="1"
          stroke="#ffaa00" 
          fillOpacity={1}
          fill="url(#colorMedium)" 
        />
        <Area 
          type="monotone" 
          dataKey="LOW" 
          stackId="1"
          stroke="#00ff7f" 
          fillOpacity={1}
          fill="url(#colorLow)" 
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export default EventTimeline;
