const express = require('express');
const bcrypt = require('bcrypt')
const app = express();
require('dotenv').config()
const jwt = require("jsonwebtoken");
const { User, Kitten } = require('./db');
// const { where } = require('sequelize/types');

const {JWT_SECRET} = process.env
const SALT_COUNT = Number(process.env.SALT_COUNT)

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.get('/', async (req, res, next) => {
  try {
    res.send(`
      <h1>Welcome to Cyber Kittens!</h1>
      <p>Cats are available at <a href="/kittens/1">/kittens/:id</a></p>
      <p>Create a new cat at <b><code>POST /kittens</code></b> and delete one at <b><code>DELETE /kittens/:id</code></b></p>
      <p>Log in via POST /login or register via POST /register</p>
    `);
  } catch (error) {
    console.error(error);
    next(error)
  }
});

// Verifies token with jwt.verify and sets req.user
// TODO - Create authentication middleware

setUser = async (req, res, next) => {
  const auth = req.header('Authorization')
  if (!auth) {
      next()
      return
  }
  const [, token] = auth.split(' ')
  const user = jwt.verify(token, JWT_SECRET)
  req.user = user
  next()
}

// POST /register
// OPTIONAL - takes req.body of {username, password} and creates a new user with the hashed password
app.post('/register', async(req, res, next) => {
  try {
    const {username, password} = req.body
    if (!username || !password) {
      return res.send('Requires username and password inputs')
    }
    const user = await User.findOne({where:{username}})
    
    if (user) {
      return res.send('User already exists')
    }

    const hashedPassword = await bcrypt.hash(password, SALT_COUNT)
  
    if (!hashedPassword) {

      return res.send('Hashing error')
    }

    createUser = await User.create({username, password:hashedPassword})
    const token = jwt.sign({id: createUser.id, username}, JWT_SECRET)
    res.send(
      {
        message: 'success',
        token: token
      }
    )
  }catch(error){
    console.error(error)
  }
});
// POST /login
// OPTIONAL - takes req.body of {username, password}, finds user by username, and compares the password with the hashed version from the DB
app.post('/login', async(req, res, next) => {
  try {
    const {username, password} = req.body
    const user = await User.findOne({where:{username}})
    
    if (!user) {
      return res.send('User does not exist')
    }
    const isMatch = await bcrypt.compare(password, user.password)
   if (!isMatch) {
    res.sendStatus(401)
    return 
  }
  const {id} = user
  const token = jwt.sign({id, username}, JWT_SECRET)
  res.send({
    message: 'success',
    token: token
  })
}catch(error){
    console.error(error)
  }
})

// GET /kittens/:id
// TODO - takes an id and returns the cat with that id
app.get('/kittens/:id', setUser, async(req, res, next) => {

  const kitten = await Kitten.findByPk(req.params.id)
  
  if (!req.user) {
    res.sendStatus(401)
    return 
  }
  if (req.user.id != kitten.userId) {
    res.sendStatus(401)
    return 
  }
  res.send({kitten})
})


// POST /kittens
// TODO - takes req.body of {name, age, color} and creates a new cat with the given name, age, and color
app.post('/kittens', setUser, async(req, res, next) => {
  if (!req.user) {
    res.sendStatus(401)
    return 
  }
  const {name, age, color} = req.body
  const kitten = await Kitten.create({where: {name:name, age, color, userId: req.user.id}})
  res.status(201).send({name, age, color})
})

// DELETE /kittens/:id
// TODO - takes an id and deletes the cat with that id
app.delete('/kittens/:id', setUser, async(req, res, next) => {

  const kitten = await Kitten.findByPk(req.params.id)

  if (!req.user) {
    res.sendStatus(401)
    return 
  }
  if (req.user.id != kitten.userId) {
    res.sendStatus(401)
    return 
  }
  await Kitten.delete({where: {id: kitten.id}})
  res.sendStatus(204)
})

// error handling middleware, so failed tests receive them
app.use((error, req, res, next) => {
  console.error('SERVER ERROR: ', error);
  if(res.statusCode < 400) res.status(500);
  res.send({error: error.message, name: error.name, message: error.message});
});

// we export the app, not listening in here, so that we can run tests
module.exports = app;
