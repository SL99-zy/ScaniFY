import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import PrivateRoute from './endpoints/privateRoute';
import { AuthProvider } from './context/AuthContext'; 
import 'bootstrap/dist/css/bootstrap.min.css';
import './index.css';
import Navbar from './malware/Navbar';
import Home from './malware/Home';
import LoginRegister from './malware/LoginRegister';
import Team from './malware/Team';
import FileUploader from './malware/FileUploader';
import Dashboard from './malware/Dashboard.jsx.backup'; // Import the Dashboard component

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
    <Router>
        <AuthProvider>
            <Navbar />
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<LoginRegister />} />
                <Route path="/register" element={<LoginRegister />} />
                <Route path="/team" element={<Team />} />

                {/* Protected Routes */}
                <Route element={<PrivateRoute />}>
                    <Route path="/test" element={<FileUploader />} />
                    <Route path="/dashboard" element={<Dashboard />} /> {/* Add Dashboard route */}
                </Route>
            </Routes>
        </AuthProvider>
    </Router>
);