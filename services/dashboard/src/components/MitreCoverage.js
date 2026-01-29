import React from 'react';

function MitreCoverage({ techniques }) {
  if (!techniques || techniques.length === 0) {
    return <div style={{ textAlign: 'center', color: '#8b949e' }}>No MITRE techniques detected</div>;
  }

  return (
    <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
      <table className="events-table">
        <thead>
          <tr>
            <th>MITRE Technique</th>
            <th>Threat Type</th>
            <th>Count</th>
          </tr>
        </thead>
        <tbody>
          {techniques.slice(0, 10).map((technique, index) => (
            <tr key={index}>
              <td style={{ fontFamily: 'monospace', color: '#00d9ff' }}>
                {technique.mitre_attack}
              </td>
              <td>{technique.threat_type.replace(/_/g, ' ')}</td>
              <td>
                <span style={{ 
                  background: 'rgba(255, 68, 68, 0.2)', 
                  padding: '0.25rem 0.75rem',
                  borderRadius: '12px',
                  fontWeight: '600'
                }}>
                  {technique.count}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default MitreCoverage;
