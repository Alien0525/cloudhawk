import React from 'react';

function StatsCards({ stats }) {
  if (!stats) {
    return <div>Loading stats...</div>;
  }

  const { realtime, severity_distribution, database } = stats;

  const cards = [
    {
      label: 'Events Processed',
      value: realtime.events_processed.toLocaleString(),
      change: `${database.events_last_hour} in last hour`,
      positive: true
    },
    {
      label: 'Threats Detected',
      value: realtime.threats_detected.toLocaleString(),
      change: `${database.threats_last_hour} in last hour`,
      positive: false
    },
    {
      label: 'Active Alerts',
      value: realtime.active_alerts,
      change: 'Requires attention',
      positive: false
    },
    {
      label: 'Critical Events',
      value: severity_distribution.CRITICAL,
      change: 'Last 24h',
      positive: false
    },
    {
      label: 'High Severity',
      value: severity_distribution.HIGH,
      change: 'Last 24h',
      positive: false
    },
    {
      label: 'Total Events',
      value: database.total_events.toLocaleString(),
      change: 'All time',
      positive: true
    }
  ];

  return (
    <>
      {cards.map((card, index) => (
        <div key={index} className="stat-card">
          <div className="stat-label">{card.label}</div>
          <div className="stat-value">{card.value}</div>
          <div className={`stat-change ${card.positive ? '' : 'negative'}`}>
            {card.change}
          </div>
        </div>
      ))}
    </>
  );
}

export default StatsCards;
