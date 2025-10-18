const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'tu_clave_secreta_super_segura_2024';

// Middleware
app.use(cors());
app.use(express.json());

// Base de datos simulada de usuarios
const users = [
    {
        id: 1,
        email: 'admin@test.com',
        password: '123456',
        name: 'Administrador'
    },
    {
        id: 2,
        email: 'user@test.com',
        password: 'password',
        name: 'Usuario de Prueba'
    },
    {
        id: 3,
        email: 'test@example.com',
        password: 'test123',
        name: 'Test User'
    }
];

// Tokens activos
const activeTokens = new Set();

// Middleware para verificar token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Token no proporcionado' 
        });
    }

    if (!activeTokens.has(token)) {
        return res.status(401).json({ 
            success: false, 
            message: 'Token inválido o expirado' 
        });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            activeTokens.delete(token);
            return res.status(403).json({ 
                success: false, 
                message: 'Token inválido' 
            });
        }
        req.userId = decoded.id;
        next();
    });
};

// Ruta de login
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    console.log('Intento de login:', email);

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email y contraseña son requeridos'
        });
    }

    const user = users.find(u => u.email === email && u.password === password);

    if (!user) {
        console.log('Credenciales incorrectas para:', email);
        return res.status(401).json({
            success: false,
            message: 'Credenciales incorrectas'
        });
    }

    // Generar token JWT
    const token = jwt.sign(
        { id: user.id, email: user.email },
        SECRET_KEY,
        { expiresIn: '24h' }
    );

    // Guardar token en la lista de activos
    activeTokens.add(token);

    console.log('Login exitoso para:', email);

    res.json({
        success: true,
        message: 'Login exitoso',
        user: {
            id: user.id,
            email: user.email,
            name: user.name,
            token: token
        }
    });
});

// Ruta para validar token
app.get('/auth/validate', verifyToken, (req, res) => {
    const user = users.find(u => u.id === req.userId);
    
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'Usuario no encontrado'
        });
    }

    res.json({
        success: true,
        message: 'Token válido',
        user: {
            id: user.id,
            email: user.email,
            name: user.name
        }
    });
});

// Ruta para logout
app.post('/auth/logout', verifyToken, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token) {
        activeTokens.delete(token);
    }

    console.log('Logout exitoso para userId:', req.userId);

    res.json({
        success: true,
        message: 'Sesión cerrada correctamente'
    });
});

// Ruta de prueba
app.get('/', (req, res) => {
    res.json({
        message: 'API de Autenticación funcionando',
        endpoints: {
            login: 'POST /auth/login',
            validate: 'GET /auth/validate',
            logout: 'POST /auth/logout'
        },
        usuarios_prueba: [
            { email: 'admin@test.com', password: '123456' },
            { email: 'user@test.com', password: 'password' },
            { email: 'test@example.com', password: 'test123' }
        ]
    });
});

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n✅ Servidor corriendo en http://localhost:${PORT}`);
    console.log('\n📝 Usuarios de prueba:');
    users.forEach(user => {
        console.log(`   - Email: ${user.email} | Password: ${user.password}`);
    });
    console.log('\n');
});