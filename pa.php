<?php
// pa_system.php - Combined Frontend and Backend File

// Start session at the very beginning
session_start();

// Check if the request is an API call by looking for the 'action' parameter
$action = $_REQUEST['action'] ?? null;

// If 'action' exists, handle it as an API request.
if ($action) {
    // --- API LOGIC START ---

    // Set header to return JSON data
    header('Content-Type: application/json');

    // --- DATABASE CONNECTION (from db_connect.php) ---
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
    date_default_timezone_set('Asia/Bangkok');

    // Database Credentials from user
    $host = 'csk.ac.th';
    $port = '3306';
    $dbname = 'cskacth_pa';
    $user = 'cskacth_pacsk';
    $pass = 'Lk31qr9FGht%yw$i';
    $charset = 'utf8mb4';

    // Data Source Name
    $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=$charset";
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    try {
        $pdo = new PDO($dsn, $user, $pass, $options);
    } catch (\PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Database connection failed.']);
        exit();
    }
    // --- END DATABASE CONNECTION ---


    // --- API FUNCTIONS AND ROUTER (from api.php) ---
    function generateId() {
        return uniqid(bin2hex(random_bytes(4)), true);
    }

    function sendResponse($data) {
        echo json_encode($data);
        exit();
    }

    function checkAdmin() {
        if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
            http_response_code(403);
            sendResponse(['status' => 'error', 'message' => 'Forbidden: Admin access required.']);
        }
    }

    // Main API Router
    switch ($action) {
        case 'login':
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$data['username']]);
            $user = $stmt->fetch();

            if ($user && password_verify($data['password'], $user['password'])) {
                unset($user['password']);
                $_SESSION['user'] = $user;
                sendResponse(['status' => 'success', 'user' => $user]);
            } else {
                http_response_code(401);
                sendResponse(['status' => 'error', 'message' => 'Invalid credentials']);
            }
            break;

        case 'logout':
            session_destroy();
            sendResponse(['status' => 'success']);
            break;

        case 'check_session':
            if (isset($_SESSION['user'])) {
                sendResponse(['status' => 'success', 'user' => $_SESSION['user']]);
            } else {
                sendResponse(['status' => 'error', 'message' => 'No active session']);
            }
            break;

        case 'get_initial_data':
            if (!isset($_SESSION['user'])) {
                http_response_code(401);
                sendResponse(['status' => 'error', 'message' => 'Unauthorized']);
            }
            $users_stmt = $pdo->query("SELECT id, username, fullName, profilePic, role FROM users");
            $fiscal_years_stmt = $pdo->query("SELECT * FROM fiscal_years");
            $submissions_stmt = $pdo->query("SELECT * FROM submissions");
            
            sendResponse([
                'status' => 'success',
                'users' => $users_stmt->fetchAll(),
                'fiscalYears' => $fiscal_years_stmt->fetchAll(),
                'submissions' => $submissions_stmt->fetchAll()
            ]);
            break;

        // --- USER MANAGEMENT (ADMIN) ---
        case 'save_user':
            checkAdmin();
            $data = json_decode(file_get_contents('php://input'), true);
            $is_new = empty($data['id']);

            if ($is_new) {
                $data['id'] = generateId();
                $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (id, username, password, fullName, profilePic, role) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$data['id'], $data['username'], $hashed_password, $data['fullName'], $data['profilePic'], $data['role']]);
            } else {
                if (!empty($data['password'])) {
                    $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("UPDATE users SET username = ?, password = ?, fullName = ?, profilePic = ?, role = ? WHERE id = ?");
                    $stmt->execute([$data['username'], $hashed_password, $data['fullName'], $data['profilePic'], $data['role'], $data['id']]);
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET username = ?, fullName = ?, profilePic = ?, role = ? WHERE id = ?");
                    $stmt->execute([$data['username'], $data['fullName'], $data['profilePic'], $data['role'], $data['id']]);
                }
            }
            $stmt = $pdo->prepare("SELECT id, username, fullName, profilePic, role FROM users WHERE id = ?");
            $stmt->execute([$data['id']]);
            sendResponse(['status' => 'success', 'user' => $stmt->fetch()]);
            break;
            
        case 'delete_user':
            checkAdmin();
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$data['id']]);
            sendResponse(['status' => 'success']);
            break;

        // --- FISCAL YEAR MANAGEMENT (ADMIN) ---
        case 'save_fiscal_year':
            checkAdmin();
            $data = json_decode(file_get_contents('php://input'), true);
            $is_new = empty($data['id']);

            if ($data['isCurrent']) {
                $pdo->query("UPDATE fiscal_years SET isCurrent = 0");
            }

            if ($is_new) {
                $data['id'] = generateId();
                $stmt = $pdo->prepare("INSERT INTO fiscal_years (id, name, isCurrent) VALUES (?, ?, ?)");
                $stmt->execute([$data['id'], $data['name'], $data['isCurrent']]);
            } else {
                $stmt = $pdo->prepare("UPDATE fiscal_years SET name = ?, isCurrent = ? WHERE id = ?");
                $stmt->execute([$data['name'], $data['isCurrent'], $data['id']]);
            }
            sendResponse(['status' => 'success', 'fiscalYear' => $data]);
            break;

        case 'delete_fiscal_year':
            checkAdmin();
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $pdo->prepare("DELETE FROM fiscal_years WHERE id = ?");
            $stmt->execute([$data['id']]);
            sendResponse(['status' => 'success']);
            break;
            
        case 'set_current_fiscal_year':
            checkAdmin();
            $data = json_decode(file_get_contents('php://input'), true);
            $pdo->query("UPDATE fiscal_years SET isCurrent = 0");
            $stmt = $pdo->prepare("UPDATE fiscal_years SET isCurrent = 1 WHERE id = ?");
            $stmt->execute([$data['id']]);
            sendResponse(['status' => 'success']);
            break;

        // --- SUBMISSIONS ---
        case 'save_submission':
            if (!isset($_SESSION['user'])) { http_response_code(401); sendResponse(['status'=>'error']);}
            $data = json_decode(file_get_contents('php://input'), true);
            $is_new = empty($data['id']);
            
            if ($is_new) {
                $data['id'] = generateId();
                $stmt = $pdo->prepare("INSERT INTO submissions (id, userId, fiscalYearId, type, fileUrl, linkUrl, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')");
                $stmt->execute([$data['id'], $_SESSION['user']['id'], $data['fiscalYearId'], $data['type'], $data['fileUrl'], $data['linkUrl']]);
            } else {
                $stmt = $pdo->prepare("UPDATE submissions SET fiscalYearId = ?, type = ?, fileUrl = ?, linkUrl = ?, status = 'pending', reason = NULL WHERE id = ? AND userId = ?");
                $stmt->execute([$data['fiscalYearId'], $data['type'], $data['fileUrl'], $data['linkUrl'], $data['id'], $_SESSION['user']['id']]);
            }
            $stmt = $pdo->prepare("SELECT * FROM submissions WHERE id = ?");
            $stmt->execute([$data['id']]);
            sendResponse(['status' => 'success', 'submission' => $stmt->fetch()]);
            break;
            
        case 'delete_submission':
            if (!isset($_SESSION['user'])) { http_response_code(401); sendResponse(['status'=>'error']);}
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $pdo->prepare("DELETE FROM submissions WHERE id = ? AND userId = ?");
            $stmt->execute([$data['id'], $_SESSION['user']['id']]);
            sendResponse(['status' => 'success']);
            break;

        case 'update_submission_status':
            if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'director') {
                http_response_code(403);
                sendResponse(['status' => 'error', 'message' => 'Forbidden: Director access required.']);
            }
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $pdo->prepare("UPDATE submissions SET status = ?, reason = ? WHERE id = ?");
            $stmt->execute([$data['status'], $data['reason'], $data['id']]);
            sendResponse(['status' => 'success']);
            break;
            
        case 'create_initial_admin':
            $count = $pdo->query("SELECT count(*) FROM users")->fetchColumn();
            if ($count == 0) {
                $id = generateId();
                $username = 'admin';
                $password = 'password';
                $fullName = 'ผู้ดูแลระบบ';
                $profilePic = 'https://placehold.co/100x100/26A69A/FFFFFF?text=A';
                $role = 'admin';
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("INSERT INTO users (id, username, password, fullName, profilePic, role) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$id, $username, $hashed_password, $fullName, $profilePic, $role]);
                
                $currentYear = date('Y') + 543;
                $pdo->prepare("INSERT INTO fiscal_years (id, name, isCurrent) VALUES (?, ?, ?)")->execute([generateId(), "ปีงบประมาณ " . ($currentYear - 1), 0]);
                $pdo->prepare("INSERT INTO fiscal_years (id, name, isCurrent) VALUES (?, ?, ?)")->execute([generateId(), "ปีงบประมาณ " . $currentYear, 1]);
                $pdo->prepare("INSERT INTO fiscal_years (id, name, isCurrent) VALUES (?, ?, ?)")->execute([generateId(), "ปีงบประมาณ " . ($currentYear + 1), 0]);

                sendResponse(['status' => 'success', 'message' => "Admin 'admin' with password 'password' created."]);
            } else {
                sendResponse(['status' => 'error', 'message' => 'Initial admin already exists.']);
            }
            break;

        default:
            http_response_code(404);
            sendResponse(['status' => 'error', 'message' => 'Action not found']);
            break;
    }

    // --- API LOGIC END ---
    exit(); // IMPORTANT: Stop script execution after handling an API request
}

// If we reach here, it means no 'action' was specified, so we render the HTML page.
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ระบบส่งเอกสาร PA (Performance Agreement)</title>
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Google Fonts: Kanit -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Kanit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- Chart.js for charts -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <!-- SweetAlert2 for beautiful alerts -->
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>

    <style>
        body {
            font-family: 'Kanit', sans-serif;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #f1f1f1; }
        ::-webkit-scrollbar-thumb { background: #26A69A; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: #1d7b71; }
        .sidebar-transition { transition: transform 0.3s ease-in-out; }
        .sidebar-hidden { transform: translateX(-100%); }
        .loader {
            border-top-color: #26A69A;
            -webkit-animation: spinner 1.5s linear infinite;
            animation: spinner 1.5s linear infinite;
        }
        @-webkit-keyframes spinner {
            0% { -webkit-transform: rotate(0deg); }
            100% { -webkit-transform: rotate(360deg); }
        }
        @keyframes spinner {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .toast { animation: toast-in 0.5s, toast-out 0.5s 2.5s; }
        @keyframes toast-in { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes toast-out { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
    </style>
</head>
<body class="bg-gray-100">

    <!-- Loading Spinner Overlay -->
    <div id="loading-overlay" class="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
        <div class="loader ease-linear rounded-full border-8 border-t-8 border-gray-200 h-32 w-32"></div>
    </div>

    <!-- Toast Notification Container -->
    <div id="toast-container" class="fixed top-5 right-5 z-50 space-y-2"></div>

    <!-- Login Page -->
    <div id="login-view" class="min-h-screen flex items-center justify-center bg-gray-50 hidden">
        <div class="max-w-md w-full bg-white p-8 rounded-xl shadow-lg space-y-6 border border-gray-200">
            <div class="text-center">
                <i data-lucide="shield-check" class="mx-auto h-12 w-12 text-teal-600"></i>
                <h2 class="mt-4 text-3xl font-extrabold text-gray-900">
                    ระบบส่งเอกสาร PA
                </h2>
                <p class="mt-2 text-sm text-gray-600">
                    Performance Agreement System
                </p>
            </div>
            <form id="login-form" class="space-y-6">
                <div>
                    <label for="username" class="sr-only">Username</label>
                    <input id="username" name="username" type="text" autocomplete="username" required
                        class="appearance-none rounded-lg relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-teal-500 focus:border-teal-500 sm:text-sm"
                        placeholder="ชื่อผู้ใช้งาน">
                </div>
                <div>
                    <label for="password" class="sr-only">Password</label>
                    <input id="password" name="password" type="password" autocomplete="current-password" required
                        class="appearance-none rounded-lg relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-teal-500 focus:border-teal-500 sm:text-sm"
                        placeholder="รหัสผ่าน">
                </div>
                <div>
                    <button type="submit"
                        class="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-teal-600 hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i data-lucide="log-in" class="h-5 w-5 text-teal-500 group-hover:text-teal-400"></i>
                        </span>
                        เข้าสู่ระบบ
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Main Application View (hidden by default) -->
    <div id="app-view" class="hidden">
        <div class="flex h-screen bg-gray-100">
            <!-- Sidebar -->
            <aside id="sidebar" class="sidebar-transition sidebar-hidden md:sidebar-hidden md:relative md:translate-x-0 fixed inset-y-0 left-0 z-30 w-64 bg-white shadow-lg overflow-y-auto">
                 <div class="flex items-center justify-between p-4 border-b">
                    <div class="flex items-center">
                        <i data-lucide="shield-check" class="h-8 w-8 text-teal-600"></i>
                        <span class="ml-3 text-xl font-bold text-gray-800">PA System</span>
                    </div>
                    <button id="close-sidebar-btn" class="md:hidden text-gray-600 hover:text-gray-800">
                        <i data-lucide="x" class="h-6 w-6"></i>
                    </button>
                </div>
                <div class="p-4" id="user-profile-sidebar">
                    <!-- User profile will be rendered here -->
                </div>
                <nav id="main-nav" class="mt-4 px-2 space-y-1">
                    <!-- Navigation links will be rendered here based on user role -->
                </nav>
                <div class="absolute bottom-0 w-full p-4 border-t">
                    <a href="#" id="logout-btn" class="flex items-center p-2 text-base font-normal text-gray-600 rounded-lg hover:bg-red-100 hover:text-red-700 group">
                        <i data-lucide="log-out" class="h-5 w-5 text-red-500"></i>
                        <span class="ml-3">ออกจากระบบ</span>
                    </a>
                </div>
            </aside>
            
            <div class="flex-1 flex flex-col overflow-hidden">
                <!-- Header -->
                <header class="flex justify-between items-center p-4 bg-white shadow-md z-10">
                    <button id="open-sidebar-btn" class="text-gray-600 focus:outline-none md:hidden">
                        <i data-lucide="menu" class="h-6 w-6"></i>
                    </button>
                    <h1 id="page-title" class="text-2xl font-semibold text-gray-800">แดชบอร์ด</h1>
                    <div id="header-user-profile" class="flex items-center space-x-3">
                       <!-- Header user profile rendered here -->
                    </div>
                </header>
                
                <!-- Main Content -->
                <main class="flex-1 overflow-x-hidden overflow-y-auto bg-gray-100 p-4 md:p-6">
                    <div id="content-container">
                        <!-- Content will be rendered here -->
                    </div>
                </main>
            </div>
        </div>
    </div>

    <!-- Modal Container -->
    <div id="modal-container" class="fixed inset-0 bg-black bg-opacity-60 z-40 flex items-center justify-center p-4 hidden">
        <!-- Modal content will be injected here -->
    </div>


    <script type="module">
        // =================================================================================
        // CONFIGURATION AND STATE MANAGEMENT
        // =================================================================================
        const API_URL = 'pa_system.php'; // API now points to this file itself
        let currentUser = null;
        let users = [];
        let fiscalYears = [];
        let submissions = [];
        let myChart = null;

        const roleMap = { admin: 'ผู้ดูแลระบบ', director: 'ผู้อำนวยการ', 'vice-director': 'รองฯ ผู้อำนวยการ', teacher: 'ครู' };
        const submissionTypeMap = { pa1: 'แบบข้อตกลง PA1', yearEnd: 'แบบรายงานสิ้นปี', presentation: 'ไฟล์นำเสนอ' };
        const statusMap = { pending: { text: 'รอตรวจ', color: 'bg-yellow-100 text-yellow-800' }, approved: { text: 'ตรวจแล้ว', color: 'bg-green-100 text-green-800' }, rejected: { text: 'ไม่ผ่าน', color: 'bg-red-100 text-red-800' }};

        // DOM Elements
        const loadingOverlay = document.getElementById('loading-overlay');
        const toastContainer = document.getElementById('toast-container');
        const loginView = document.getElementById('login-view');
        const appView = document.getElementById('app-view');
        const loginForm = document.getElementById('login-form');
        const contentContainer = document.getElementById('content-container');
        const pageTitle = document.getElementById('page-title');
        const mainNav = document.getElementById('main-nav');
        const userProfileSidebar = document.getElementById('user-profile-sidebar');
        const headerUserProfile = document.getElementById('header-user-profile');
        const logoutBtn = document.getElementById('logout-btn');
        const openSidebarBtn = document.getElementById('open-sidebar-btn');
        const closeSidebarBtn = document.getElementById('close-sidebar-btn');
        const sidebar = document.getElementById('sidebar');
        const modalContainer = document.getElementById('modal-container');

        // =================================================================================
        // API HELPER
        // =================================================================================
        const apiRequest = async (action, method = 'GET', body = null) => {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' },
            };
            if (body) {
                options.body = JSON.stringify(body);
            }
            // The URL includes the action parameter to be caught by the PHP logic at the top of the file.
            const url = `${API_URL}?action=${action}`;
            try {
                const response = await fetch(url, options);
                if (response.status === 401) {
                    handleLogout(false);
                    return null;
                }
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return await response.json();
            } catch (error) {
                console.error('API Request Error:', error);
                showToast('เกิดข้อผิดพลาดในการเชื่อมต่อเซิร์ฟเวอร์', 'error');
                return null;
            }
        };

        // =================================================================================
        // UTILITY FUNCTIONS
        // =================================================================================
        const showLoading = () => loadingOverlay.classList.remove('hidden');
        const hideLoading = () => loadingOverlay.classList.add('hidden');
        
        const showToast = (message, type = 'success') => {
            const colors = { success: 'bg-teal-500', error: 'bg-red-500', info: 'bg-blue-500' };
            const icons = { success: 'check-circle', error: 'alert-triangle', info: 'info' }
            const toast = document.createElement('div');
            toast.className = `toast flex items-center p-4 mb-4 text-white ${colors[type]} rounded-lg shadow-lg`;
            toast.innerHTML = `<i data-lucide="${icons[type]}" class="w-5 h-5 mr-3"></i><span>${message}</span>`;
            toastContainer.appendChild(toast);
            lucide.createIcons();
            setTimeout(() => toast.remove(), 3000);
        };
        
        const openModal = (title, content) => {
             modalContainer.innerHTML = `
                <div class="bg-white rounded-lg shadow-xl w-full max-w-2xl transform transition-all" onclick="event.stopPropagation()">
                    <div class="flex justify-between items-center p-4 border-b">
                        <h3 class="text-xl font-semibold text-gray-800">${title}</h3>
                        <button onclick="window.closeModal()" class="text-gray-400 hover:text-gray-600"><i data-lucide="x" class="w-6 h-6"></i></button>
                    </div><div class="p-6">${content}</div></div>`;
            modalContainer.classList.remove('hidden');
            lucide.createIcons();
        };

        window.closeModal = () => {
            modalContainer.classList.add('hidden');
            modalContainer.innerHTML = '';
        };

        const getCurrentFiscalYear = () => fiscalYears.find(fy => fy.isCurrent) || (fiscalYears.length > 0 ? fiscalYears[0] : null);
        
        // =================================================================================
        // INITIALIZATION
        // =================================================================================
        const initializeApp = async () => {
            const session = await apiRequest('check_session');
            if (session && session.status === 'success') {
                currentUser = session.user;
                await loadInitialData();
                showAppView();
            } else {
                showLoginView();
            }
            lucide.createIcons();
        };

        const loadInitialData = async () => {
            const data = await apiRequest('get_initial_data');
            if(data && data.status === 'success'){
                users = data.users;
                fiscalYears = data.fiscalYears.map(fy => ({...fy, isCurrent: !!parseInt(fy.isCurrent)}));
                submissions = data.submissions;
            } else {
                // This logic attempts to create an initial admin if the database is empty.
                const checkUsers = await apiRequest('get_initial_data');
                if (checkUsers && checkUsers.users.length === 0) {
                     await apiRequest('create_initial_admin', 'POST');
                     showToast('สร้างผู้ดูแลระบบเริ่มต้นแล้ว (admin/password)', 'info');
                     await loadInitialData();
                } else {
                     showToast('ไม่สามารถโหลดข้อมูลเริ่มต้นได้', 'error');
                }
            }
        };

        // =================================================================================
        // AUTHENTICATION & NAVIGATION
        // =================================================================================
        const handleLogin = async (e) => {
            e.preventDefault();
            showLoading();
            const username = loginForm.username.value;
            const password = loginForm.password.value;
            
            const result = await apiRequest('login', 'POST', { username, password });
            hideLoading();
            if (result && result.status === 'success') {
                currentUser = result.user;
                await loadInitialData();
                showAppView();
                showToast('เข้าสู่ระบบสำเร็จ', 'success');
            } else {
                showToast('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'error');
            }
        };
        
        const handleLogout = (showConfirmation = true) => {
            const performLogout = async () => {
                await apiRequest('logout', 'POST');
                currentUser = null;
                users = [];
                fiscalYears = [];
                submissions = [];
                showLoginView();
            };

            if (showConfirmation) {
                 Swal.fire({ title: 'ยืนยันการออกจากระบบ?', icon: 'warning', showCancelButton: true, confirmButtonColor: '#26A69A', cancelButtonColor: '#EF5350', confirmButtonText: 'ใช่, ออกจากระบบ', cancelButtonText: 'ยกเลิก' })
                 .then((result) => { if (result.isConfirmed) performLogout(); });
            } else {
                performLogout();
            }
        };
        
        const showLoginView = () => {
            loginView.classList.remove('hidden');
            loginView.style.display = 'flex';
            appView.style.display = 'none';
            hideLoading();
        };

        const showAppView = () => {
            loginView.style.display = 'none';
            appView.style.display = 'block';
            updateSidebar();
            navigateTo(currentUser.role + '-dashboard');
        };

        const updateSidebar = () => {
            userProfileSidebar.innerHTML = `<div class="flex flex-col items-center p-2 rounded-lg bg-gray-50"><img src="${currentUser.profilePic}" alt="Profile" class="w-20 h-20 rounded-full object-cover border-4 border-teal-200"><h4 class="mt-2 font-semibold text-gray-700">${currentUser.fullName}</h4><p class="text-sm text-gray-500">${roleMap[currentUser.role]}</p></div>`;
            headerUserProfile.innerHTML = `<span class="hidden md:block text-right"><div class="font-medium text-gray-800">${currentUser.fullName}</div><div class="text-xs text-gray-500">${roleMap[currentUser.role]}</div></span><img src="${currentUser.profilePic}" alt="Profile" class="w-10 h-10 rounded-full object-cover">`;
            const commonLinks = [{ view: `${currentUser.role}-dashboard`, icon: 'layout-dashboard', text: 'แดชบอร์ด' },{ view: 'profile-settings', icon: 'user-cog', text: 'แก้ไขข้อมูลส่วนตัว' },];
            const roleSpecificLinks = { admin: [{ view: 'admin-users', icon: 'users', text: 'จัดการผู้ใช้งาน' },{ view: 'admin-fiscal-years', icon: 'calendar-days', text: 'จัดการปีงบประมาณ' },{ view: 'admin-summary', icon: 'file-pie-chart', text: 'สรุปผลเอกสาร' },], director: [{ view: 'director-review-pa1', icon: 'file-check-2', text: 'ตรวจงาน (PA1)' },{ view: 'director-review-yearEnd', icon: 'file-check-2', text: 'ตรวจงาน (รายงานสิ้นปี)' },{ view: 'director-review-presentation', icon: 'file-check-2', text: 'ตรวจงาน (ไฟล์นำเสนอ)' },], 'vice-director': [{ view: 'user-submissions', icon: 'file-up', text: 'ส่งงานเอกสาร' },], teacher: [{ view: 'user-submissions', icon: 'file-up', text: 'ส่งงานเอกสาร' },]};
            const links = [...commonLinks, ...(roleSpecificLinks[currentUser.role] || [])];
            mainNav.innerHTML = links.map(link => `<a href="#" class="nav-link flex items-center p-2 text-base font-normal text-gray-600 rounded-lg hover:bg-teal-100 hover:text-teal-700 group" data-view="${link.view}"><i data-lucide="${link.icon}" class="w-5 h-5 text-gray-500 group-hover:text-teal-600"></i><span class="ml-3">${link.text}</span></a>`).join('');
            mainNav.querySelectorAll('.nav-link').forEach(link => { link.addEventListener('click', (e) => { e.preventDefault(); if(sidebar.classList.contains('md:sidebar-hidden')) { sidebar.classList.add('sidebar-hidden'); } navigateTo(link.dataset.view); }); });
        };

        const navigateTo = (view) => {
            showLoading();
            mainNav.querySelectorAll('.nav-link').forEach(link => { link.classList.remove('bg-teal-100', 'text-teal-700', 'font-semibold'); if (link.dataset.view === view) { link.classList.add('bg-teal-100', 'text-teal-700', 'font-semibold'); pageTitle.textContent = link.querySelector('span').textContent; } });
            setTimeout(() => { contentContainer.innerHTML = ''; renderView(view); hideLoading(); lucide.createIcons(); }, 300);
        };

        const renderView = (view) => {
            switch(view) {
                case 'admin-dashboard': renderAdminDashboard(); break;
                case 'admin-users': renderAdminUsers(); break;
                case 'admin-fiscal-years': renderAdminFiscalYears(); break;
                case 'admin-summary': renderAdminSummary(); break;
                case 'director-dashboard': renderDirectorDashboard(); break;
                case 'director-review-pa1': renderDirectorReview('pa1'); break;
                case 'director-review-yearEnd': renderDirectorReview('yearEnd'); break;
                case 'director-review-presentation': renderDirectorReview('presentation'); break;
                case 'teacher-dashboard': case 'vice-director-dashboard': renderUserDashboard(); break;
                case 'user-submissions': renderUserSubmissions(); break;
                case 'profile-settings': renderProfileSettings(); break;
                default: contentContainer.innerHTML = `<p>Page not found: ${view}</p>`;
            }
        };

        // =================================================================================
        // RENDER FUNCTIONS AND HANDLERS
        // =================================================================================
        
        const renderAdminDashboard = () => {
            const currentYear = getCurrentFiscalYear();
            let selectedYearId = currentYear ? currentYear.id : (fiscalYears[0] ? fiscalYears[0].id : null);
            const updateDashboardStats = (yearId) => {
                const teachers = users.filter(u => u.role === 'teacher').length;
                const vices = users.filter(u => u.role === 'vice-director').length;
                const pa1Submissions = submissions.filter(s => s.type === 'pa1' && s.fiscalYearId === yearId).length;
                const yearEndSubmissions = submissions.filter(s => s.type === 'yearEnd' && s.fiscalYearId === yearId).length;
                const presentationSubmissions = submissions.filter(s => s.type === 'presentation' && s.fiscalYearId === yearId).length;
                document.getElementById('stat-teachers').textContent = teachers;
                document.getElementById('stat-vices').textContent = vices;
                document.getElementById('stat-pa1').textContent = pa1Submissions;
                document.getElementById('stat-yearEnd').textContent = yearEndSubmissions;
                document.getElementById('stat-presentation').textContent = presentationSubmissions;
            };
            const renderChart = () => {
                const ctx = document.getElementById('submissionsChart').getContext('2d');
                const years = [...fiscalYears].sort((a,b) => a.name.localeCompare(b.name));
                const labels = years.map(fy => fy.name);
                const pa1Data = years.map(fy => submissions.filter(s => s.fiscalYearId === fy.id && s.type === 'pa1').length);
                const yearEndData = years.map(fy => submissions.filter(s => s.fiscalYearId === fy.id && s.type === 'yearEnd').length);
                const presentationData = years.map(fy => submissions.filter(s => s.fiscalYearId === fy.id && s.type === 'presentation').length);
                if (myChart) myChart.destroy();
                myChart = new Chart(ctx, { type: 'bar', data: { labels: labels, datasets: [{ label: 'แบบข้อตกลง PA1', data: pa1Data, backgroundColor: '#26A69A' }, { label: 'รายงานสิ้นปี', data: yearEndData, backgroundColor: '#FFCA28' }, { label: 'ไฟล์นำเสนอ', data: presentationData, backgroundColor: '#EF5350' }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }});
            }
            const yearOptions = fiscalYears.map(fy => `<option value="${fy.id}" ${fy.id === selectedYearId ? 'selected' : ''}>${fy.name}</option>`).join('');
            contentContainer.innerHTML = `<div class="space-y-6"><div class="bg-white p-4 rounded-lg shadow"><label for="year-filter">ปีงบประมาณ:</label><select id="year-filter" class="rounded-md border-gray-300">${yearOptions}</select></div><div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4"><div>...</div></div><div class="bg-white p-5 rounded-lg shadow"><div class="h-96"><canvas id="submissionsChart"></canvas></div></div></div>`;
            contentContainer.innerHTML = `<div class="space-y-6"> <div class="bg-white p-4 rounded-lg shadow"><label for="year-filter" class="font-medium text-gray-700">ปีงบประมาณ:</label><select id="year-filter" class="mt-1 block w-full md:w-1/4 rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500 sm:text-sm">${yearOptions}</select></div> <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4"><div class="bg-white p-5 rounded-lg shadow flex items-center space-x-4"><div class="bg-blue-100 p-3 rounded-full"><i data-lucide="user-square" class="h-6 w-6 text-blue-500"></i></div><div><p class="text-sm text-gray-500">จำนวนครูทั้งหมด</p><p id="stat-teachers" class="text-2xl font-bold text-gray-800">0</p></div></div><div class="bg-white p-5 rounded-lg shadow flex items-center space-x-4"><div class="bg-indigo-100 p-3 rounded-full"><i data-lucide="user-check" class="h-6 w-6 text-indigo-500"></i></div><div><p class="text-sm text-gray-500">จำนวน รองฯ ผอ. ทั้งหมด</p><p id="stat-vices" class="text-2xl font-bold text-gray-800">0</p></div></div><div class="bg-white p-5 rounded-lg shadow flex items-center space-x-4"><div class="bg-green-100 p-3 rounded-full"><i data-lucide="file-text" class="h-6 w-6 text-green-500"></i></div><div><p class="text-sm text-gray-500">ส่ง PA1</p><p id="stat-pa1" class="text-2xl font-bold text-gray-800">0</p></div></div><div class="bg-white p-5 rounded-lg shadow flex items-center space-x-4"><div class="bg-yellow-100 p-3 rounded-full"><i data-lucide="file-bar-chart-2" class="h-6 w-6 text-yellow-500"></i></div><div><p class="text-sm text-gray-500">ส่งรายงานสิ้นปี</p><p id="stat-yearEnd" class="text-2xl font-bold text-gray-800">0</p></div></div><div class="bg-white p-5 rounded-lg shadow flex items-center space-x-4"><div class="bg-red-100 p-3 rounded-full"><i data-lucide="presentation" class="h-6 w-6 text-red-500"></i></div><div><p class="text-sm text-gray-500">ส่งไฟล์นำเสนอ</p><p id="stat-presentation" class="text-2xl font-bold text-gray-800">0</p></div></div></div> <div class="bg-white p-5 rounded-lg shadow"><h3 class="text-lg font-semibold text-gray-800 mb-4">ภาพรวมการส่งเอกสาร</h3><div class="h-96"><canvas id="submissionsChart"></canvas></div></div></div>`;
            updateDashboardStats(selectedYearId);
            renderChart();
            document.getElementById('year-filter').addEventListener('change', (e) => updateDashboardStats(e.target.value));
        };
        
        const renderAdminUsers = () => {
            const tableRows = users.map((user, index) => `<tr class="border-b hover:bg-gray-50"><td class="p-3">${index + 1}</td><td class="p-3"><div class="flex items-center space-x-3"><img src="${user.profilePic}" class="w-10 h-10 rounded-full"><span>${user.fullName}</span></div></td><td class="p-3">${roleMap[user.role]}</td><td class="p-3"><button onclick="window.handleEditUser('${user.id}')">Edit</button><button ${user.role==='admin'?'disabled':''} onclick="window.handleDeleteUser('${user.id}')">Delete</button></td></tr>`).join('');
            contentContainer.innerHTML = `<div class="bg-white p-6 rounded-lg shadow"><div class="flex justify-between items-center mb-4"><h2 class="text-xl font-bold text-gray-800">จัดการผู้ใช้งาน</h2><button id="add-user-btn" class="flex items-center bg-teal-600 text-white px-4 py-2 rounded-lg hover:bg-teal-700 transition-colors"><i data-lucide="plus" class="w-5 h-5 mr-2"></i> เพิ่มผู้ใช้งาน </button></div><div class="overflow-x-auto"><table class="w-full"><thead class="bg-gray-50"><tr><th>ลำดับ</th><th>ชื่อ-นามสกุล</th><th>สิทธิ์</th><th>จัดการ</th></tr></thead><tbody>${tableRows}</tbody></table></div></div>`;
            document.getElementById('add-user-btn').addEventListener('click', () => handleEditUser(null));
        };

        window.handleEditUser = (userId) => {
            const user = userId ? users.find(u => u.id === userId) : null;
            openModal(user ? 'แก้ไขผู้ใช้' : 'เพิ่มผู้ใช้', `... form html ...`);
            const formContent = `
                <form id="user-form" class="space-y-4">
                    <input type="hidden" name="id" value="${user?.id || ''}">
                    <div><label>ชื่อ-นามสกุล</label><input type="text" name="fullName" value="${user?.fullName || ''}" required class="w-full rounded-md"></div>
                    <div><label>Username</label><input type="text" name="username" value="${user?.username || ''}" required class="w-full rounded-md"></div>
                    <div><label>Password</label><input type="password" name="password" ${user?'':'required'} placeholder="Leave blank to keep same" class="w-full rounded-md"></div>
                    <div><label>สิทธิ์</label><select name="role" class="w-full rounded-md">${Object.entries(roleMap).map(([key, value]) => `<option value="${key}" ${user?.role === key ? 'selected' : ''}>${value}</option>`).join('')}</select></div>
                    <div><label>URL รูปโปรไฟล์</label><input type="text" name="profilePic" value="${user?.profilePic || ''}" class="w-full rounded-md"></div>
                    <button type="submit">บันทึก</button>
                </form>`;
            openModal(user ? 'แก้ไขผู้ใช้งาน' : 'เพิ่มผู้ใช้งานใหม่', formContent);
            document.getElementById('user-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const userData = Object.fromEntries(new FormData(e.target).entries());
                const result = await apiRequest('save_user', 'POST', userData);
                if (result && result.status === 'success') {
                    if (userData.id) users[users.findIndex(u => u.id === userData.id)] = result.user;
                    else users.push(result.user);
                    closeModal();
                    navigateTo('admin-users');
                }
            });
        };

        window.handleDeleteUser = (userId) => {
            Swal.fire({ title: 'ยืนยันการลบ?', icon: 'warning', showCancelButton: true }).then(async (result) => {
                if (result.isConfirmed) {
                    const apiResult = await apiRequest('delete_user', 'POST', { id: userId });
                    if(apiResult && apiResult.status === 'success') {
                        users = users.filter(u => u.id !== userId);
                        navigateTo('admin-users');
                    }
                }
            });
        };

        // ... Implement all other render and handler functions in a similar API-driven way ...

        // =================================================================================
        // EVENT LISTENERS
        // =================================================================================
        document.addEventListener('DOMContentLoaded', initializeApp);
        loginForm.addEventListener('submit', handleLogin);
        logoutBtn.addEventListener('click', () => handleLogout(true));
        
        openSidebarBtn.addEventListener('click', () => sidebar.classList.remove('sidebar-hidden'));
        closeSidebarBtn.addEventListener('click', () => sidebar.classList.add('sidebar-hidden'));
        modalContainer.addEventListener('click', closeModal);

    </script>
</body>
</html>
