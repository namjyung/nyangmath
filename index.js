const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const PORT = process.env.PORT || 3000;

// MySQL 연결 설정
const connection = mysql.createConnection({
    host: 'svc.sel4.cloudtype.app',
    user: 'nyangmath_user',
    port: 31896,
    password: '12345',
    database: 'nyangmath'
});

// 정적 파일을 제공하는 경로 설정
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
}));

// 회원가입 요청 처리
app.post('/submit-signup', async (req, res) => {
    const { newUsername, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ success: false, message: '비밀번호가 일치하지 않습니다.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    connection.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [newUsername, hashedPassword],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ success: false, message: '회원가입에 실패했습니다.' });
            }
            res.json({ success: true, message: '회원가입에 성공했습니다.' });
        }
    );
});

// 로그인 요청 처리
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    connection.query(query, [username], async (err, results) => {
        if (err) {
            console.error('DB 에러:', err);
            return res.status(500).json({ success: false, message: 'DB 에러' });
        }

        if (results.length > 0) {
            const user = results[0];
            console.log('입력된 비밀번호:', password);
            console.log('DB에 저장된 해시된 비밀번호:', user.password);
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                req.session.username = user.username;
                return res.json({ success: true, username: user.username });
            } else {
                console.log('비밀번호 불일치');
                return res.status(401).json({ success: false, message: '비밀번호가 일치하지 않습니다.' });
            }
        } else {
            console.log('사용자 없음');
            return res.status(404).json({ success: false, message: '존재하지 않는 사용자입니다.' });
        }
    });
});

// 로그아웃 처리
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('로그아웃 에러');
        }
        res.redirect('/');
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});

