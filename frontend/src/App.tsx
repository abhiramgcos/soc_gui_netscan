import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout/Layout';
import Dashboard from './components/Dashboard/Dashboard';
import ScanList from './components/Scans/ScanList';
import ScanDetail from './components/Scans/ScanDetail';
import HostTable from './components/Hosts/HostTable';
import HostDetail from './components/Hosts/HostDetail';
import FirmwareList from './components/Firmware/FirmwareList';
import FirmwareDetail from './components/Firmware/FirmwareDetail';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans" element={<ScanList />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
        <Route path="/hosts" element={<HostTable />} />
        <Route path="/hosts/:mac" element={<HostDetail />} />
        <Route path="/firmware" element={<FirmwareList />} />
        <Route path="/firmware/:id" element={<FirmwareDetail />} />
      </Routes>
    </Layout>
  );
}

export default App;
