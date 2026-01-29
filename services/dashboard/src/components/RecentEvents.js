import React from 'react';

function RecentEvents({ events }) {
  if (!events || events.length === 0) {
    return <div style={{ textAlign: 'center', color: '#8b949e' }}>No recent events</div>;
  }

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="events-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>User</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Threats</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <tr key={index}>
              <td>{formatTime(event.timestamp)}</td>
              <td>{event.event_name}</td>
              <td>{event.user || 'N/A'}</td>
              <td>{event.source_ip}</td>
              <td>
                <span className={`severity-badge ${event.severity}`}>
                  {event.severity}
                </span>
              </td>
              <td>{event.threat_count || 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default RecentEvents;
