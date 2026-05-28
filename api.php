<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
require_once 'config.php';

$request_method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

$headers = getallheaders();
$auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : '';
$token = '';
if (preg_match('/Bearer\s(\S+)/', $auth_header, $matches)) {
    $token = $matches[1];
}

$user = null;
if ($token) {
    $user = verifyJWT($token);
}

switch ($action) {
    case 'register':
        if ($request_method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
        }
        handleRegister($pdo);
        break;
        
    case 'login':
        if ($request_method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
        }
        handleLogin($pdo);
        break;
        
    case 'orders':
        if ($request_method === 'POST') {
            if (!$user) {
                http_response_code(401);
                echo json_encode(['error' => 'Authentication required']);
                break;
            }
            handlePlaceOrder($pdo, $user);
        } elseif ($request_method === 'GET') {
            if (!$user) {
                http_response_code(401);
                echo json_encode(['error' => 'Authentication required']);
                break;
            }
            handleGetOrders($pdo, $user);
        } else {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
        }
        break;
        
    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
}

function handleRegister($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $name = trim($data['name'] ?? '');
    $email = trim($data['email'] ?? '');
    $password = $data['password'] ?? '';
    
    if (!$name || !$email || !$password) {
        http_response_code(400);
        echo json_encode(['error' => 'All fields required']);
        return;
    }
    
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        http_response_code(400);
        echo json_encode(['error' => 'Email already registered']);
        return;
    }
    
    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    if ($stmt->execute([$name, $email, $hashed])) {
        $userId = $pdo->lastInsertId();
        $user = ['id' => $userId, 'name' => $name, 'email' => $email];
        $token = generateJWT($user);
        echo json_encode(['token' => $token, 'user' => $user]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Registration failed']);
    }
}

function handleLogin($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $email = trim($data['email'] ?? '');
    $password = $data['password'] ?? '';
    
    if (!$email || !$password) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password required']);
        return;
    }
    
    $stmt = $pdo->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user || !password_verify($password, $user['password'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
        return;
    }
    
    $token = generateJWT($user);
    echo json_encode(['token' => $token, 'user' => ['id' => $user['id'], 'name' => $user['name'], 'email' => $user['email']]]);
}

function handlePlaceOrder($pdo, $user) {
    $data = json_decode(file_get_contents('php://input'), true);
    $items = $data['items'] ?? [];
    $total = $data['total'] ?? 0;
    $address = trim($data['address'] ?? '');
    $phone = trim($data['phone'] ?? '');
    $notes = trim($data['notes'] ?? '');
    
    if (empty($items) || !$address || !$phone) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields']);
        return;
    }
    
    $stmt = $pdo->prepare("INSERT INTO orders (user_id, user_name, user_email, items, total, address, phone, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $itemsJson = json_encode($items);
    $success = $stmt->execute([$user['id'], $user['name'], $user['email'], $itemsJson, $total, $address, $phone, $notes]);
    
    if ($success) {
        $orderId = $pdo->lastInsertId();
        echo json_encode(['message' => 'Order placed successfully', 'orderId' => $orderId]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to place order']);
    }
}

function handleGetOrders($pdo, $user) {
    $stmt = $pdo->prepare("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$user['id']]);
    $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($orders as &$order) {
        $order['items'] = json_decode($order['items'], true);
    }
    echo json_encode(['orders' => $orders]);
}
?>