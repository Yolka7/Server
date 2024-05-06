const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // Добавим cookie-parser
const { body, validationResult } = require('express-validator');


const app = express();

app.use(bodyParser.json());
app.use(cookieParser()); // Подключим cookie-parser
app.use(cors())

app.get('/user/info', authenticateToken, (req, res) => {
  res.json(req.user);
});

//-----------------------------------------------------------------------------------
const { Sequelize } = require('sequelize');

// Создаем экземпляр Sequelize, передавая параметры подключения к базе данных
const sequelize = new Sequelize('users', 'root', '1111', {
  host: '127.0.0.1',
  dialect: 'mysql',
  storage: 'C:\\Users\\dmitriyb\\Desktop\\325235\\users.sql'
});

// Определяем модели для таблиц в базе данных
const User = sequelize.define('users', {
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
sequelize.sync({ force: true }).then(() => {              //!!!!! 
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

const users = [
{ username: 'user1', role: roles.USER, department: 'HR', password: '$2b$10$3p/1X3.y7wxI6vZDzOabwulq/t.g9XrTr7p.2UNHiJg.15VWIR1ou' }, // hashed password: 'password'
{ username: 'admin1', role: roles.ADMIN, department: 'IT', password: '$2b$10$3p/1X3.y7wxI6vZDzOabwulq/t.g9XrTr7p.2UNHiJg.15VWIR1ou' },
{ username: 'moderator1', role: roles.MODERATOR, department: 'Finance', password: '$2b$10$3p/1X3.y7wxI6vZDzOabwulq/t.g9XrTr7p.2UNHiJg.15VWIR1ou' },
];

// Регистрация пользователя
app.post('/register', [
  body('username').isString().notEmpty(),
  body('firstName').isString().notEmpty(),
  body('lastName').isString().notEmpty(),
  body('password').isString().notEmpty(),
  body('department').isIn(departments),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, firstName, lastName, password, department } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    // Попытка создать нового пользователя в базе данных
    const newUser = await User.create({
      username,
      firstName,
      lastName,
      password: hashedPassword,
      role: roles.USER,
      department,
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Маршрут для аутентификации пользователя
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Ищем пользователя в базе данных
  const user = await User.findOne({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, role: user.role, department: user.department }, 'your-secret-key');

  // Устанавливаем cookie с токеном
  res.cookie('token', token, { httpOnly: true });

  // Устанавливаем cookie с ролью пользователя
  res.cookie('role', user.role, { httpOnly: false });

  res.json({ token });
});

// Маршрут для выхода пользователя
app.post('/logout', (req, res) => {
// Очищаем cookie с токеном
res.clearCookie('token');

// Очищаем cookie с ролью пользователя
res.clearCookie('role');

res.json({ success: true });
});

// Корневой маршрут
app.get('/', (req, res) => {
// Проверяем наличие токена в cookie
const token = req.cookies.token;
const role = req.cookies.role;

if (token) {
// Если токен есть, выводим информацию о текущем пользователе
jwt.verify(token, 'your-secret-key', (err, user) => {
if (!err) {
res.send(`Welcome, ${user.username}! Role: ${role}, Department: ${user.department}`);
return;
}
});
}

// Если токена нет, выводим приветственное сообщение
res.send('Welcome to the Role-based Application System');
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

// Пример защищенного маршрута (требует валидного JWT)
app.get('/protected', authenticateToken, (req, res) => {
res.json({ message: 'This is a protected route', user: req.user });
});

// Маршрут для отправки заявки
app.post('/apply', authenticateToken, (req, res) => {
const { username, role, department, description } = req.body;

// Проверка наличия отдела в списке
if (!departments.includes(department)) {
return res.status(400).json({ error: 'Invalid department' });
}

applications.push({
username, role, department, description });
res.json({ success: true });
});

// Маршрут для отправки заявки
app.post('/submit-application', authenticateToken, (req, res) => {
const { title, text } = req.body;

const token = req.cookies.token;
jwt.verify(token, 'your-secret-key', (err, user) => {
if (err) {
return res.status(403).json({ error: 'Invalid token' });
}

applications.push({ username: user.username, role: user.role, department: user.department, title, text });
res.json({ success: true });
});
});

// Маршрут для просмотра и удаления заявок
app.get('/view-applications', authenticateToken, (req, res) => {
const token = req.cookies.token;
jwt.verify(token, 'your-secret-key', (err, user) => {
if (err) {
return res.status(403).json({ error: 'Invalid token' });
}

// Проверяем, является ли текущий пользователь администратором или модератором
if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
// Если пользователь имеет права, выводим список заявок
res.json(applications);
} else {
// Если пользователь не является администратором или модератором, выводим ошибку доступа
res.status(403).json({ error: 'Access denied' });
}
});
});

// Маршрут для удаления заявки
app.delete('/delete-application/:id', authenticateToken, (req, res) => {
const token = req.cookies.token;
jwt.verify(token, 'your-secret-key', (err, user) => {
if (err) {
return res.status(403).json({ error: 'Invalid token' });
}

const id = parseInt(req.params.id);

// Проверяем, является ли текущий пользователь администратором или модератором
if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
// Если пользователь имеет права, удаляем заявку
const index = applications.findIndex(app => app.id === id);
if (index !== -1) {
applications.splice(index, 1);
res.json({ success: true });
} else {
res.status(404).json({ error: 'Application not found' });
}
} else {
// Если пользователь не является администратором или модератором, выводим ошибку доступа
res.status(403).json({ error: 'Access denied' });
}
});
});

const PORT = 3000;
app.listen(PORT, () => {
console.log(`Server is running on port ${PORT}`);
});

const mysql = require("mysql2");

const pool = mysql.createPool({
    connectionLimit: 5,
    host: "localhost",
    user: "root",
    database: "usersdb2",
    password: "123456"
  });
   
  app.set("view engine", "hbs");
   
  // получение списка пользователей
  app.get("/", function(req, res){
      pool.query("SELECT * FROM users", function(err, data) {
        if(err) return console.log(err);
        res.render("index.hbs", {
            users: data
        });
      });
  });
  // возвращаем форму для добавления данных
  app.get("/create", function(req, res){
      res.render("create.hbs");
  });
  // получаем отправленные данные и добавляем их в БД 
  // app.post("/create", urlencodedParser, function (req, res) {
           
  //     if(!req.body) return res.sendStatus(400);
  //     const name = req.body.name;
  //     const age = req.body.age;
  //     pool.query("INSERT INTO users (name, age) VALUES (?,?)", [name, age], function(err, data) {
  //       if(err) return console.log(err);
  //       res.redirect("/");
  //     });
  // });
   
  // получем id редактируемого пользователя, получаем его из бд и отправлям с формой редактирования
  app.get("/edit/:id", function(req, res){
    const id = req.params.id;
    pool.query("SELECT * FROM users WHERE id=?", [id], function(err, data) {
      if(err) return console.log(err);
       res.render("edit.hbs", {
          user: data[0]
      });
    });
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
  app.post("/delete/:id", function(req, res){
            
    const id = req.params.id;
    pool.query("DELETE FROM users WHERE id=?", [id], function(err, data) {
      if(err) return console.log(err);
      res.redirect("/");
    });
  });
   
  app.listen(3001, function(){
    console.log("Сервер ожидает подключения...");
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