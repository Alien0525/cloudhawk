import React from 'react';

function ActiveAlerts({ alerts }) {
  if (!alerts || alerts.length === 0) {
    return null;
  }

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  return (
    <div>
      <h2 style={{ marginBottom: '1rem' }}>🚨 Active Security Alerts</h2>
      <div className="alert-list">
        {alerts.map((alert, index) => (
          <div key={index} className={`alert-item ${alert.severity}`}>
            <div className="alert-header">
              <span className={`alert-severity ${alert.severity}`}>
                {alert.severity}
              </span>
              <span className="alert-time">{formatTime(alert.timestamp)}</span>
            </div>
            <div className="alert-description">
              <strong>{alert.event_name}</strong>
              {alert.threats && alert.threats.length > 0 && (
                <div style={{ marginTop: '0.5rem' }}>
                  {alert.threats.map((threat, i) => (
                    <div key={i} style={{ fontSize: '0.9rem', color: '#b0b0b0' }}>
                      • {threat.description}
                    </div>
                  ))}
                </div>
              )}
              <div style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: '#8b949e' }}>
                User: {alert.user || 'N/A'} | IP: {alert.source_ip || 'N/A'}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default ActiveAlerts;
