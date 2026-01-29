import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

function TopUsers({ users, isIp = false }) {
  if (!users || users.length === 0) {
    return <div style={{ textAlign: 'center', color: '#8b949e' }}>No data available</div>;
  }

  // Format data for chart
  const chartData = users.map(user => ({
    name: isIp ? user.source_ip : user.user_name,
    'Total Events': user.event_count,
    'Suspicious': user.suspicious_count,
    'High Severity': user.high_severity_count
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2a3f5f" />
        <XAxis 
          dataKey="name" 
          stroke="#8b949e"
          angle={-45}
          textAnchor="end"
          height={100}
        />
        <YAxis stroke="#8b949e" />
        <Tooltip 
          contentStyle={{ 
            background: '#1e2640', 
            border: '1px solid #2a3f5f',
            borderRadius: '8px'
          }}
        />
        <Legend />
        <Bar dataKey="Total Events" fill="#00d9ff" />
        <Bar dataKey="Suspicious" fill="#ffaa00" />
        <Bar dataKey="High Severity" fill="#ff4444" />
      </BarChart>
    </ResponsiveContainer>
  );
}

export default TopUsers;
