const User = require('./models/User')
const Role = require('./models/Role')
const bcrypt = require('bcryptjs')
const { validationResult } = require('express-validator')
const jwt = require('jsonwebtoken')
const { secret } = require('./config')

const generateAccessToken = (id, roles) => {
    const payload = {
        id,
        roles,
    }
    return jwt.sign(payload, secret, { expiresIn: '24h' })
}

class authController {
    async registration(request, response) {
        try {
            const errors = validationResult(request)
            if (!errors.isEmpty()) {
                return response
                    .status(400)
                    .json({ message: 'Ошибка при регистрации', errors })
            }
            const { username, password } = request.body
            const candidate = await User.findOne({ username })
            if (candidate) {
                response.status(400).json({
                    message: 'Пользователь с таким именем уже существует',
                })
            }
            const hashPassword = bcrypt.hashSync(password, 7)
            const userRole = await Role.findOne({ value: 'USER' })
            const user = new User({
                username,
                password: hashPassword,
                roles: [userRole.value],
            })
            await user.save()
            return response.json({
                message: 'Пользователь успешно зарегистрирован',
            })
        } catch (error) {
            console.log(error)
            response.status(400).json({ message: 'Registration error' })
        }
    }

    async login(request, response) {
        try {
            const { username, password } = request.body
            const user = await User.findOne({ username })
            if (!username) {
                return response
                    .status(400)
                    .json({ message: `Ползователь ${username} не найден` })
            }
            const validPaswword = bcrypt.compareSync(password, user.password)
            if (!validPaswword) {
                return response
                    .status(400)
                    .json({ message: 'Введен неверный пароль' })
            }
            const token = generateAccessToken(user._id, user.roles)
            return response.json({token})
        } catch (error) {
            console.log(error)
            response.status(400).json({ message: 'Login error' })
        }
    }

    async getUsers(request, response) {
        try {
            // для создания первоначальных ролей
            // const userRole = new Role()
            // const adminRole = new Role({ value: 'ADMIN' })
            // await userRole.save()
            // await adminRole.save()
            const users = await User.find()
            response.json(users)
        } catch (error) {
            console.log(error)
        }
    }
}

module.exports = new authController()
