import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './App.css';
import EventTimeline from './components/EventTimeline';
import ThreatMap from './components/ThreatMap';
import StatsCards from './components/StatsCards';
import RecentEvents from './components/RecentEvents';
import ActiveAlerts from './components/ActiveAlerts';
import TopUsers from './components/TopUsers';
import MitreCoverage from './components/MitreCoverage';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';

function App() {
  const [stats, setStats] = useState(null);
  const [recentEvents, setRecentEvents] = useState([]);
  const [recentThreats, setRecentThreats] = useState([]);
  const [activeAlerts, setActiveAlerts] = useState([]);
  const [timeline, setTimeline] = useState({});
  const [topUsers, setTopUsers] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [mitreCoverage, setMitreCoverage] = useState([]);
  const [connected, setConnected] = useState(false);
  const [ws, setWs] = useState(null);

  // Fetch initial data
  const fetchData = useCallback(async () => {
    try {
      const [
        statsRes,
        eventsRes,
        threatsRes,
        alertsRes,
        timelineRes,
        usersRes,
        ipsRes,
        mitreRes
      ] = await Promise.all([
        axios.get(`${API_BASE_URL}/api/stats`),
        axios.get(`${API_BASE_URL}/api/events/recent?limit=50`),
        axios.get(`${API_BASE_URL}/api/threats/recent?limit=50`),
        axios.get(`${API_BASE_URL}/api/alerts/active`),
        axios.get(`${API_BASE_URL}/api/analytics/timeline?hours=24`),
        axios.get(`${API_BASE_URL}/api/analytics/top-users?limit=10`),
        axios.get(`${API_BASE_URL}/api/analytics/top-ips?limit=10`),
        axios.get(`${API_BASE_URL}/api/mitre-attack/coverage`)
      ]);

      setStats(statsRes.data);
      setRecentEvents(eventsRes.data.events);
      setRecentThreats(threatsRes.data.threats);
      setActiveAlerts(alertsRes.data.alerts);
      setTimeline(timelineRes.data.timeline);
      setTopUsers(usersRes.data.users);
      setTopIps(ipsRes.data.ips);
      setMitreCoverage(mitreRes.data.techniques);
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  }, []);

  // Setup WebSocket connection
  useEffect(() => {
    fetchData();

    // Connect to WebSocket
    const websocket = new WebSocket(`${WS_URL}/ws/realtime`);

    websocket.onopen = () => {
      console.log('WebSocket connected');
      setConnected(true);
    };

    websocket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      if (message.type === 'alert') {
        // New alert received
        setActiveAlerts(prev => [message.data, ...prev].slice(0, 20));
        
        // Show notification
        if (Notification.permission === 'granted') {
          new Notification('CloudHawk Alert', {
            body: `${message.data.severity}: ${message.data.event_name}`,
            icon: '/logo192.png'
          });
        }
      } else if (message.type === 'stats') {
        // Stats update
        setStats(message.data);
      }
    };

    websocket.onclose = () => {
      console.log('WebSocket disconnected');
      setConnected(false);
    };

    websocket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    setWs(websocket);

    // Request notification permission
    if (Notification.permission === 'default') {
      Notification.requestPermission();
    }

    // Cleanup
    return () => {
      if (websocket.readyState === WebSocket.OPEN) {
        websocket.close();
      }
    };
  }, [fetchData]);

  // Refresh data periodically
  useEffect(() => {
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div className="App">
      <header className="App-header">
        <div className="header-content">
          <div className="logo-section">
            <h1>🦅 CloudHawk</h1>
            <p className="subtitle">Real-Time Cloud Threat Detection & Response</p>
          </div>
          <div className="connection-status">
            <span className={`status-indicator ${connected ? 'connected' : 'disconnected'}`}>
              {connected ? '● Live' : '○ Disconnected'}
            </span>
          </div>
        </div>
      </header>

      <main className="App-main">
        {/* Stats Cards */}
        <section className="stats-section">
          <StatsCards stats={stats} />
        </section>

        {/* Active Alerts */}
        {activeAlerts.length > 0 && (
          <section className="alerts-section">
            <ActiveAlerts alerts={activeAlerts} />
          </section>
        )}

        {/* Timeline and Map */}
        <section className="visualization-section">
          <div className="viz-grid">
            <div className="viz-item timeline-item">
              <h2>Event Timeline (24h)</h2>
              <EventTimeline data={timeline} />
            </div>
            <div className="viz-item map-item">
              <h2>Threat Distribution</h2>
              <ThreatMap threats={recentThreats} />
            </div>
          </div>
        </section>

        {/* Analytics */}
        <section className="analytics-section">
          <div className="analytics-grid">
            <div className="analytics-item">
              <h2>Top Active Users</h2>
              <TopUsers users={topUsers} />
            </div>
            <div className="analytics-item">
              <h2>Suspicious IPs</h2>
              <TopUsers users={topIps} isIp={true} />
            </div>
            <div className="analytics-item">
              <h2>MITRE ATT&CK Coverage</h2>
              <MitreCoverage techniques={mitreCoverage} />
            </div>
          </div>
        </section>

        {/* Recent Events */}
        <section className="events-section">
          <h2>Recent Security Events</h2>
          <RecentEvents events={recentEvents} />
        </section>
      </main>

      <footer className="App-footer">
        <p>CloudHawk Security Platform v1.0 | Powered by AI & Machine Learning</p>
      </footer>
    </div>
  );
}

export default App;
