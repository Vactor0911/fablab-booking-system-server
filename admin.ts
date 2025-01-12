// 어드민 관련 API

import express from "express";
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate";
import { db } from "./index.ts";

const router = express.Router();

// 모든 예약 조회 (관리자 전용)
router.get("/reservations", authenticateToken, authorizeAdmin, (req, res) => {
  db.query("SELECT * FROM book")
    .then((rows: any) => {
      res.status(200).json({ success: true, reservations: rows });
    })
    .catch((err) => {
      console.error("예약 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "예약 조회 중 오류가 발생했습니다." });
    });
});

// 특정 사용자 삭제 (관리자 전용)
router.delete("/users/:userId", authenticateToken, authorizeAdmin, (req, res) => {
  const { userId } = req.params;

  db.query("DELETE FROM user WHERE user_id = ?", [userId])
    .then(() => {
      res.status(200).json({ success: true, message: "사용자가 삭제되었습니다." });
    })
    .catch((err) => {
      console.error("사용자 삭제 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "사용자 삭제 중 오류가 발생했습니다." });
    });
});

export default router;
