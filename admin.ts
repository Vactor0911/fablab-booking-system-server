// 어드민 관련 API

import express from "express";
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate";
import { db } from "./index.ts";
import RateLimit from "express-rate-limit";
import csurf from "csurf";
import validator from "validator"; // 유효성 검사 라이브러리
import nodemailer from "nodemailer";  // 이메일 전송 라이브러리


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


// 특정 좌석 정보 조회 API (관리자 전용)
router.get("/seats/:seatName", authenticateToken, authorizeAdmin, async (req, res) => {
  const { seatName } = req.params;

  try {
    // 좌석 정보와 예약 정보를 조인하여 가져오기
    const [seat] = await db.query(
      `
      SELECT 
        s.seat_id,
        s.name AS seat_name,
        s.type,
        s.pc_surpport,
        s.image_path,
        s.basic_manners,
        s.warning,
        DATE_FORMAT(b.book_date, '%Y-%m-%d') AS reservation_date,
        TIME_FORMAT(b.book_date, '%H:%i') AS reservation_time,
        u.id AS user_student_id,
        u.name AS user_name
      FROM seat s
      LEFT JOIN book b ON s.seat_id = b.seat_id AND b.state = 'book'
      LEFT JOIN user u ON b.user_id = u.user_id
      WHERE s.name = ?
      `,
      [seatName]
    );

    if (!seat) {
      res.status(404).json({
        success: false,
        message: "해당 좌석 정보를 찾을 수 없습니다.",
      });
      return;
    }

    // API 응답
    res.status(200).json({
      success: true,
      seat: {
        seatId: seat.seat_id,
        seatName: seat.seat_name,
        reservationDate: seat.reservation_date || "예약 없음",
        reservationTime: seat.reservation_time || "예약 없음",
        userStudentId: seat.user_student_id || "없음",
        userName: seat.user_name || "없음",
        basicManners: seat.basic_manners,
        warning: seat.warning,
        imagePath: seat.image_path || "/placeholder.jpg", // 기본 이미지 경로
      },
    });
  } catch (err) {
    console.error("좌석 정보 조회 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "좌석 정보를 조회하는 중 오류가 발생했습니다.",
    });
  }
});


// 강제 퇴실 API 시작
router.post("/force-exit", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
    const { seatId, reason, start_date, end_date } = req.body;

    if (!seatId || !reason) {
       res.status(400).json({
        success: false,
        message: "좌석 ID와 퇴실 사유는 필수 항목입니다.",
      });
      return;
    }
    // 특수문자 검증 (허용되지 않는 특수문자 체크)
    if (!validator.isLength(reason, { max: 100 }) || /[`<>]/.test(reason)) {
      res.status(400).json({
        success: false,
        message: "퇴실 사유는 최대 100자의 텍스트이며, <, >, ` 문자는 허용되지 않습니다.",
      });
      return;
    }

    try {
      const connection = await db.getConnection(); // 트랜잭션 시작
      await connection.beginTransaction();

      // 예약 정보 가져오기
      const [reservation] = await connection.query(
        `SELECT b.book_id, b.user_id, u.email, u.name, s.name AS seat_name 
         FROM book b
         LEFT JOIN user u ON b.user_id = u.user_id
         LEFT JOIN seat s ON b.seat_id = s.seat_id
         WHERE b.seat_id = ? AND b.state = 'book'`,
        [seatId]
      );

      if (!reservation) {
        res.status(404).json({
          success: false,
          message: "해당 좌석에 활성화된 예약이 없습니다.",
        });
        return;
      }

      const { book_id, email, name, seat_name } = reservation;

      // 예약 상태를 'cancel'로 업데이트
      await connection.query(`UPDATE book SET state = 'cancel' WHERE book_id = ?`, [book_id]);

      // 예약 로그 기록
      await connection.query(
        `INSERT INTO book_log (book_id, log_date, type) VALUES (?, NOW(), 'cancel')`,
        [book_id]
      );

      // 예약 제한 테이블에 기록 추가
      await connection.query(
        `INSERT INTO book_restriction (seat_id, admin_id, start_date, end_date, reason) 
         VALUES (?, ?, NOW(), NOW(), ?)`,
        [seatId, req.user.userId, reason]
      );

      // 이메일 전송
      const transporter = nodemailer.createTransport({
        service: "gmail",
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        auth: {
          user: process.env.NODEMAILER_USER,
          pass: process.env.NODEMAILER_PASS,
        },
      });

      const mailOptions = {
        from: `"FabLab 예약 시스템" <${process.env.NODEMAILER_USER}>`,
        to: email,
        subject: `[FabLab 예약 시스템] ${seat_name} 강제 퇴실 알림`,
        html: `
          <h1>강제 퇴실 알림</h1>
          <p>${name}님,</p>
          <p>다음 좌석에 대한 예약이 관리자에 의해 강제 퇴실 처리되었습니다</p>
          <ul>
            <li><strong>좌석 번호:</strong> ${seat_name}</li>
            <li><strong>퇴실 사유:</strong> ${reason}</li>
          </ul>
          <p>문의사항이 있으시면 관리자에게 문의하세요.</p>
        `,
      };

      await transporter.sendMail(mailOptions);

      // 트랜잭션 커밋
      await connection.commit();

      res.status(200).json({
        success: true,
        message: "강제 퇴실 처리가 완료되었으며, 이메일이 전송되었습니다.",
      });
    } catch (err) {
      console.error("강제 퇴실 처리 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "강제 퇴실 처리 중 서버 오류가 발생했습니다.",
      });
    }
  }
);
// 강제 퇴실 API 끝





export default router;
