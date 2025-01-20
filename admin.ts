// 어드민 관련 API

import express from "express";
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate";
import { db } from "./index.ts";
import RateLimit from "express-rate-limit";
import csurf from "csurf";


// Rate Limit 설정
const limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 요청 횟수
});

const router = express.Router();

// CSRF 보호 설정
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: false, // HTTPS 환경에서는 true로 설정
    sameSite: "strict", // CSRF 보호를 위한 설정
  },
});

// 모든 좌석과 예약 정보 조회 (관리자 전용) - 이미 route가 /admin이므로 /admin/seats로 설정하지 않아도 됨
router.get("/seats", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const rows = await db.query(
      `SELECT 
        s.seat_id, 
        s.name AS seat_name, 
        b.user_id, 
        u.id AS user_student_id, -- 학번 추가
        u.name AS user_name, 
        b.state 
      FROM seat s
      LEFT JOIN book b ON s.seat_id = b.seat_id AND b.state = 'book'
      LEFT JOIN user u ON b.user_id = u.user_id
      `
    );

    res.status(200).json({
      success: true,
      seats: rows,
    });
  } catch (err) {
    console.error("좌석 정보 조회 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "좌석 정보를 불러오는 중 서버 오류가 발생했습니다.",
    });
  }
});



export default router;
