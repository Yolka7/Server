const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // Добавим cookie-parser
const {body, validationResult} = require('express-validator');


const app = express();

app.use(bodyParser.json());
app.use(cookieParser()); // Подключим cookie-parser
app.use(cors())

app.get('/user/info', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Защита маршрутов с использованием JWT
function authenticateToken(req, res, next) {
    const token = req.headers.authorization.split(' ')[1]; // Получаем токен из cookie
    if (!token) return res.status(401).json({error: 'Access denied'});

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({error: 'Invalid token'});
        req.user = user;
        next();
    });
}

//-----------------------------------------------------------------------------------
const {Sequelize} = require('sequelize');

// Создаем экземпляр Sequelize, передавая параметры подключения к базе данных
const sequelize = new Sequelize('postgres://anelfer:anelfer@localhost:5432/postgres');

// Определяем модели для таблиц в базе данных
const User = sequelize.define('users_qwerty', {
    username: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
    },
    firstName: {
        type: Sequelize.STRING,
        allowNull: false,
    },
    lastName: {
        type: Sequelize.STRING,
        allowNull: false,
    },
    password: {
        type: Sequelize.STRING,
        allowNull: false,
    },
    role: {
        type: Sequelize.STRING,
        allowNull: false,
    },
    department: {
        type: Sequelize.STRING,
        allowNull: false,
    },
});


// Синхронизируем модели с базой данных
sequelize.sync().then(() => {              //!!!!!
    console.log('База данных синхронизирована');
});
//-----------------------------------------------------------------------------------

const roles = {
    USER: 'user',
    ADMIN: 'admin',
    MODERATOR: 'moderator',
};

const applications = [];
const departments = ['HR', 'IT', 'Finance'];

// Регистрация пользователя
app.post('/user/register', [
    body('username').isString().notEmpty(),
    body('firstName').isString().notEmpty(),
    body('lastName').isString().notEmpty(),
    body('password').isString().notEmpty(),
    body('department').isIn(departments),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }

    const {username, firstName, lastName, password, department} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        // Попытка создать нового пользователя в базе данных
        const newUser = await User.create({
            username,
            firstName,
            lastName,
            password: hashedPassword,
            role: roles.ADMIN,
            department,
        });

        const token = jwt.sign({username, role: newUser.role, department: newUser.department}, 'your-secret-key');
        res.json(token);
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({error: 'Internal Server Error'});
    }
});

// Маршрут для аутентификации пользователя
app.post('/user/login', async (req, res) => {
    const {username, password} = req.body;

    // Ищем пользователя в базе данных
    const user = await User.findOne({where: {username}});

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({error: 'Invalid credentials'});
    }

    const token = jwt.sign({username, role: user.role, department: user.department}, 'your-secret-key');
    res.json({token});
});

// Корневой маршрут
app.get('/', (req, res) => {
    res.send('Welcome to the Role-based Application System');
});

// Пример защищенного маршрута (требует валидного JWT)
app.get('/protected', authenticateToken, (req, res) => {
    res.json({message: 'This is a protected route', user: req.user});
});

app.get('/ticket/:id', authenticateToken, (req, res) => {
    console.log("[INFO] GET /ticket/:id", req.params.id);

    res.json(applications[parseInt(req.params.id) - 1]);
});

// Маршрут для отправки заявки
app.post('/ticket', authenticateToken, (req, res) => {
    const {theme, category, description} = req.body;
    const user = req.user
    console.log(`[INFO] POST /ticket with user ${user.username} `, req.body);
    applications.push({id: (applications.length + 1).toString(), username: user.username, role: user.role, department: user.department, theme, category, description, status: "Отправлено", answer: ""});
    res.json({success: true});
});

// Маршрут для просмотра и удаления заявок
app.get('/tickets', authenticateToken, (req, res) => {
    const user = req.user
    const { done } = req.query; // Получаем параметр done из запроса

    // Проверяем, является ли текущий пользователь администратором или модератором
    if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
        let filteredApplications = applications;

        // Если параметр done равен true, фильтруем тикеты по статусу "Закрыто"
        if (done === 'true') {
            filteredApplications = filteredApplications.filter(app => app.status === 'Закрыто');
        } else {
            filteredApplications = filteredApplications.filter(app => app.status !== 'Закрыто');
        }

        res.json({ length: filteredApplications.length, applications: filteredApplications });
    } else {
        let userApplications = applications.filter(app => app.username === user.username);

        // Если параметр done равен true, фильтруем тикеты по статусу "Закрыто"
        if (done === 'true') {
            userApplications = userApplications.filter(app => app.status === 'Закрыто');
        } else {
            userApplications = userApplications.filter(app => app.status !== 'Закрыто');
        }

        res.json({ length: userApplications.length, applications: userApplications });
    }
});

// Маршрут для удаления заявки
app.delete('/ticket/:id', authenticateToken, (req, res) => {
    const id = parseInt(req.params.id);
    const user = req.user

    // Проверяем, является ли текущий пользователь администратором или модератором
    if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
        // Если пользователь имеет права, удаляем заявку
        const index = applications.findIndex(app => app.id === id);
        if (index !== -1) {
            applications.splice(index, 1);
            res.json({success: true});
        } else {
            res.status(200).json({error: 'Application not found'});
        }
    } else {
        // Если пользователь не является администратором или модератором, выводим ошибку доступа
        res.status(403).json({error: 'Access denied'});
    }
});

app.patch('/ticket/:id', authenticateToken, (req, res) => {
    const id = parseInt(req.params.id);
    const user = req.user;
    const updatedData = req.body;

    console.log(`[INFO] PATCH /ticket/:id ${id} with user ${user.username} data ${JSON.stringify(updatedData)}`);

    // Проверяем, является ли текущий пользователь администратором или модератором
    if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
        // Если пользователь имеет права, ищем заявку для редактирования
        const ticket = applications.find(app => app.id === id.toString());
        console.log(applications)
        console.log(`Find ticket: ${JSON.stringify(ticket)}`)
        if (ticket) {
            // Обновляем только переданные поля
            Object.keys(updatedData).forEach(key => {
                if (ticket[key] !== undefined) {
                    ticket[key] = updatedData[key];
                }
            });
            res.json({success: true, updatedTicket: ticket});
        } else {
            res.status(200).json({error: 'Ticket not found'});
        }
    } else {
        // Если пользователь не является администратором или модератором, выводим ошибку доступа
        res.status(403).json({error: 'Access denied'});
    }
});


const PORT = 3002;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// получем id редактируемого пользователя, получаем его из бд и отправлям с формой редактирования
app.get("/user/edit/:id", function (req, res) {
    const id = req.params.id;
    // User.update
    // pool.query("SELECT * FROM users WHERE id=?", [id], function (err, data) {
    //     if (err) return console.log(err);
    //     res.render("edit.hbs", {
    //         user: data[0]
    //     });
    // });
});
// получаем отредактированные данные и отправляем их в БД
// app.post("/edit", urlencodedParser, function (req, res) {

//   if(!req.body) return res.sendStatus(400);
//   const name = req.body.name;
//   const age = req.body.age;
//   const id = req.body.id;

//   pool.query("UPDATE users SET name=?, age=? WHERE id=?", [name, age, id], function(err, data) {
//     if(err) return console.log(err);
//     res.redirect("/");
//   });
// });

// получаем id удаляемого пользователя и удаляем его из бд
app.post("/user/delete/:id", function (req, res) {

    // const id = req.params.id;
    // pool.query("DELETE FROM users WHERE id=?", [id], function (err, data) {
    //     if (err) return console.log(err);
    //     res.redirect("/");
    // });
});

// что бы установить все зависимости npm i
// запустить приложение npm run start

// почитай про REST API и CRUD


//пример документации
// url = http://localhost:3000

// Регистрация - POST url/auth/registration
// body = {
// password: string,
// login: string,
// }

// Регистрация - POST url/auth/login
// body = {
// password: string,
// login: string,
// }


// Регистрация - POST url/task/
// body = {
// title: string,
// description: string,
// }


// Эталон CRUD операций
//создать         POST url/task
//Получить все    GET url/task
//Получить одну   GET url/task/:id
//удалить одну    DELETE url/task/:id
// изменить одну  PUT url/task/:id

// Проверка - вывести всех зарегистрированных пользователей