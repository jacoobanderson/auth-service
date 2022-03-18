import express from 'express'
import { router as accountRouter } from './account-router.js'
export const router = express.Router()
router.use('/', accountRouter)
