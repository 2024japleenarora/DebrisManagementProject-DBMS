const API_BASE_URL = 'http://localhost:3000/api';

// --- Utility Functions ---

function getAuthToken() {
    return localStorage.getItem('token');
}

function getUserRole() {
    return localStorage.getItem('role');
}

// Simple temporary message box replacement for alert()
function showGlobalAlert(message, type = 'success') {
    const box = document.getElementById('alert-box');
    box.textContent = message;
    box.style.opacity = '1';
    
    // Reset classes
    box.classList.remove('bg-green-500', 'bg-red-500', 'bg-yellow-500');

    if (type === 'success') {
        box.classList.add('bg-green-500');
    } else if (type === 'error') {
        box.classList.add('bg-red-500');
    } else {
        box.classList.add('bg-yellow-500');
    }

    box.style.display = 'block';

    setTimeout(() => {
        box.style.opacity = '0';
        setTimeout(() => box.style.display = 'none', 500);
    }, 3000);
}

// --- View Management ---

function toggleView(isAuthenticated) {
    const authView = document.getElementById('auth-view');
    const dashboardView = document.getElementById('dashboard-view');
    const adminNotice = document.getElementById('admin-notice');
    const reportForm = document.getElementById('report-form');
    
    if (isAuthenticated) {
        authView.classList.add('hidden');
        dashboardView.classList.remove('hidden');
        
        const role = getUserRole();
        const username = localStorage.getItem('username');
        
        document.getElementById('user-info').textContent = `Logged in as: ${username} (${role.toUpperCase()})`;
        
        // --- Admin Mode Logic ---
        if (role !== 'admin') {
            // Disable the form for non-admins
            reportForm.classList.add('opacity-50', 'pointer-events-none');
            adminNotice.textContent = 'User access denied';
            adminNotice.classList.replace('text-red-500', 'text-gray-400');
        } else {
            // Enable the form for admins
            reportForm.classList.remove('opacity-50', 'pointer-events-none');
            adminNotice.textContent = 'Admin Only';
            adminNotice.classList.replace('text-gray-400', 'text-red-500');
        }
        
        // Load initial data for the dashboard
        loadReports();
        loadDrones();

    } else {
        authView.classList.remove('hidden');
        dashboardView.classList.add('hidden');
    }
}


// --- API Handlers ---

// Handles both Register and Login
async function handleAuth(url, data) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        
        if (!response.ok) {
            showGlobalAlert(result.error || 'Authentication failed.', 'error');
            return false;
        }

        // Store token and user info from the server response
        localStorage.setItem('token', result.token);
        localStorage.setItem('username', result.username);
        localStorage.setItem('role', result.role);
        
        showGlobalAlert(`Welcome, ${result.username}! Logged in as ${result.role}.`, 'success');
        toggleView(true);
        return true;

    } catch (error) {
        console.error('Network Error:', error);
        showGlobalAlert('Network error during authentication. Is the server running?', 'error');
        return false;
    }
}

// Submits a new report (Admin function)
async function submitReport(e) {
    e.preventDefault();
    
    // The HTML form is visually disabled, but we double-check the role on the client-side
    if (getUserRole() !== 'admin') {
        return showGlobalAlert('Only Admins can create new reports.', 'error');
    }

    const token = getAuthToken();
    if (!token) return showGlobalAlert('Not logged in.', 'error');

    const form = e.target;
    const data = {
        SiteID: parseInt(form['site-id'].value),
        DroneID: parseInt(form['drone-id'].value),
        EstimatedQuantity: parseFloat(form['quantity'].value),
        LocationCoords: form['coords'].value
    };

    try {
        const response = await fetch(`${API_BASE_URL}/reports`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        
        if (!response.ok) {
            // Displays Foreign Key errors (like invalid SiteID) from the server
            return showGlobalAlert(result.error || 'Failed to create report.', 'error');
        }
        
        showGlobalAlert('Success: New report created and pending dispatch!', 'success');
        loadReports(); // Refresh the report list to show the new task

    } catch (error) {
        showGlobalAlert('Network error while creating report.', 'error');
    }
}

// Runs the Nearest Neighbor Dispatch Algorithm
async function dispatchTruck(taskId) {
    const token = getAuthToken();
    if (!token) return showGlobalAlert('Not logged in.', 'error');
    
    // This is an Admin-only function, so we verify the role
    if (getUserRole() !== 'admin') {
        return showGlobalAlert('Access Denied. Only an Admin can dispatch a truck.', 'error');
    }

    // Simple confirmation replacement for alert()
    if (!confirm(`Confirm dispatch for Task ID ${taskId}? This is an irreversible action.`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/dispatch/${taskId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            return showGlobalAlert(result.error || 'Dispatch failed.', 'error');
        }

        showGlobalAlert(`DISPATCH SUCCESS: ${result.message} - Nearest Depot: ${result.depot}`, 'success');
        loadReports(); // Refresh the report list to show 'Dispatched' status
        
    } catch (error) {
        showGlobalAlert('Network error during dispatch.', 'error');
    }
}

// --- Data Loading Functions ---

async function loadReports() {
    const reportsContainer = document.getElementById('reports-container');
    reportsContainer.innerHTML = '<p class="text-gray-500">Loading reports...</p>';
    
    const token = getAuthToken();
    if (!token) {
        reportsContainer.innerHTML = '<p class="text-red-500">Please log in to view reports.</p>';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/reports`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401 || response.status === 403) {
            // Token is invalid/expired/missing, force logout
            localStorage.clear();
            toggleView(false);
            throw new Error('Session expired. Please log in again.');
        }

        const data = await response.json();
        
        if (data.length === 0) {
            reportsContainer.innerHTML = '<p class="text-gray-500">No debris reports found.</p>';
            return;
        }

        reportsContainer.innerHTML = '';
        const userIsAdmin = getUserRole() === 'admin';

        data.forEach(item => {
            const isPending = item.TaskStatus === 'Pending';
            const isCompleted = item.TaskStatus === 'Completed';
            const statusColor = isCompleted ? 'text-green-600' : isPending ? 'text-yellow-600' : 'text-blue-600';
            
            // Dispatch button logic: only visible for Pending tasks AND only if user is Admin
            const dispatchButton = isPending && userIsAdmin
                ? `<button onclick="dispatchTruck(${item.TaskID})" class="w-full py-2 px-4 rounded-md text-sm font-medium text-white bg-orange-500 hover:bg-orange-600 transition-colors duration-150">Find & Dispatch Truck</button>`
                : isPending && !userIsAdmin
                ? `<span class="text-xs text-gray-500 p-2 border border-gray-300 rounded-md block text-center">Admin Dispatch Required</span>`
                : '';

            const depotInfo = item.AssignedDepotName ? `<span class="font-medium text-xs text-blue-600">Dispatched to: ${item.AssignedDepotName}</span>` : 'Not yet dispatched';

            const itemHtml = `
                <div class="report-item grid grid-cols-4 items-center">
                    <div class="col-span-3 space-y-1">
                        <div class="flex justify-between items-center pr-4">
                            <h3 class="font-bold text-gray-700">Task #${item.TaskID} (Site ${item.SiteID})</h3>
                            <span class="${statusColor} font-semibold">${item.TaskStatus}</span>
                        </div>
                        <p class="text-sm">Est. Quantity: <span class="font-medium">${item.EstimatedQuantity} kg</span></p>
                        <p class="text-xs text-gray-500">Coords: ${item.LocationCoords} | Detected: ${new Date(item.DetectionTime).toLocaleDateString()}</p>
                        <p class="text-xs">Drone: ${item.DroneModel} (ID: ${item.DroneID}) | Operator: ${item.OperatorName || 'N/A'}</p>
                    </div>
                    <div class="col-span-1 flex flex-col justify-center h-full items-end space-y-2">
                        <div class="text-right w-full">
                           ${depotInfo}
                        </div>
                        ${dispatchButton}
                    </div>
                </div>
            `;
            reportsContainer.innerHTML += itemHtml;
        });

    } catch (error) {
        console.error("Error fetching reports:", error);
        reportsContainer.innerHTML = `<p class="text-red-500">Failed to load reports: ${error.message}</p>`;
    }
}

async function loadDrones() {
    const droneContainer = document.getElementById('drone-container');
    droneContainer.innerHTML = '<p class="text-gray-500">Loading drones...</p>';
    
    const token = getAuthToken();
    if (!token) {
        droneContainer.innerHTML = '<p class="text-red-500">Please log in to view fleet status.</p>';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/drones`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        // Handle unauthorized response if session has expired
        if (response.status === 401 || response.status === 403) {
            throw new Error('Session expired.');
        }

        const drones = await response.json();
        
        droneContainer.innerHTML = '';
        drones.forEach(drone => {
            droneContainer.innerHTML += `
                <div class="border-b pb-2 mb-2">
                    <p class="font-semibold text-gray-800">${drone.Model} (ID: ${drone.DroneID})</p>
                    <p class="text-sm text-gray-600">Battery: ${drone.BatteryLife}% | Zone: Z${drone.AssignedZoneID}</p>
                </div>
            `;
        });

    } catch (error) {
        droneContainer.innerHTML = `<p class="text-red-500">Failed to load drones: ${error.message}</p>`;
    }
}

// --- Event Listeners ---

document.addEventListener('DOMContentLoaded', () => {
    // 1. Check Auth Status on Load
    const token = getAuthToken();
    toggleView(!!token);

    // 2. Handle Login/Register Form Submission
    const authForm = document.getElementById('auth-form');
    let isRegistering = false;

    document.getElementById('switch-to-register').addEventListener('click', () => {
        isRegistering = !isRegistering;
        document.getElementById('login-button').textContent = isRegistering ? 'Register' : 'Log In';
        document.getElementById('switch-to-register').textContent = isRegistering ? 'Log In Instead' : 'Register Here';
    });

    authForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        const endpoint = isRegistering ? `${API_BASE_URL}/auth/register` : `${API_BASE_URL}/auth/login`;
        handleAuth(endpoint, { username, password });
    });

    // 3. Handle Logout
    document.getElementById('logout-button').addEventListener('click', () => {
        localStorage.clear();
        showGlobalAlert('Logged out successfully.', 'success');
        toggleView(false);
    });

    // 4. Handle Report Form Submission (Admin Only)
    document.getElementById('report-form').addEventListener('submit', submitReport);
    
    // Make dispatchTruck available globally (it's called from HTML buttons)
    window.dispatchTruck = dispatchTruck; 
});