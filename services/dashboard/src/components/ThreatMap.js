import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

function ThreatMap({ threats }) {
  if (!threats || threats.length === 0) {
    return <div style={{ textAlign: 'center', color: '#8b949e' }}>No threats detected</div>;
  }

  // Aggregate threats by type
  const threatCounts = {};
  
  threats.forEach(threatList => {
    if (Array.isArray(threatList)) {
      threatList.forEach(threat => {
        const type = threat.type || 'unknown';
        threatCounts[type] = (threatCounts[type] || 0) + 1;
      });
    }
  });

  const chartData = Object.entries(threatCounts).map(([type, count]) => ({
    name: type.replace(/_/g, ' ').toUpperCase(),
    value: count
  }));

  const COLORS = ['#ff0000', '#ff6600', '#ffaa00', '#00d9ff', '#00ff7f', '#9d00ff', '#ff00ff'];

  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
          outerRadius={80}
          fill="#8884d8"
          dataKey="value"
        >
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip 
          contentStyle={{ 
            background: '#1e2640', 
            border: '1px solid #2a3f5f',
            borderRadius: '8px'
          }}
        />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}

export default ThreatMap;
