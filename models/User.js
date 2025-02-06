/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - username
 *         - password
 *         - name
 *         - department
 *         - location
 *         - email
 *         - contact
 *       properties:
 *         username:
 *           type: string
 *         password:
 *           type: string
 *         name:
 *           type: string
 *         department:
 *           type: string
 *         location:
 *           type: string
 *         email:
 *           type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         contact:
 *           type: string
 */

const express = require('express');
const mongoose = require('mongoose');



const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  department: { type: String, required: true },
  location: { type: String, required: true },
  email: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  contact: { type: String, required: true}
});

const User = mongoose.model('User', UserSchema,'User');
module.exports = User;