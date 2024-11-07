const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const app = express();

// DBに格納するユーザーデータ
const userDB = [
	{ username: "test", password: bcrypt.hashSync("password", 10) },
];

// セッション設定
// express-session
app.use(session({ secret: "secretKey" }));
// passport session
app.use(passport.initialize());
app.use(passport.session());

// LocalStrategy(ユーザー名・パスワードでの認証)の設定
passport.use(
	new LocalStrategy(async (username, password, done) => {
		const user = userDB.find((user) => user.username === username);

		if (!user) {
			// ユーザーが見つからない場合
			return done(null, false);
		}
		// ハッシュ化したPWの突き合わせ。入力されたpasswordから、DBに保存されたハッシュ値を比較する
		const match = await bcrypt.compare(password, user.password);
		if (match) {
			return done(null, user); // ログイン成功
		} else {
			return done(null, false); // ログイン失敗
		}
	})
);

// 認証に成功した時にsessionにusernameを保存するための記述
passport.serializeUser((user, done) => done(null, user.username));
// sessionからusernameを取り出して検証するための記述
passport.deserializeUser((username, done) => {
	const user = userDB.find((user) => user.username === username);
	done(null, user);
});

// ユーザー一覧取得エンドポイント
app.get("/users", (req, res) => {
	// sessionから情報を取得して認証
	if (req.isAuthenticated()) {
		res.json(userDB);
	} else {
		res.status(401).json({ message: "ログインが必要です！" });
	}
});

// ログインエンドポイント
app.get("/login", (req, res) => {
	const { username, password } = req.query;
	if (!username || !password) {
		return res.status(400).json({
			message: "usernameとpasswordが必要です",
		});
	}

	// 最初に設定したLocalStrategy(ユーザー名とパスワードでの認証)を使ってログイン
	passport.authenticate("local", (err, user) => {
		if (!user) return res.status(401).json({ message: "ログイン失敗！" });

		// sessionにログイン情報を格納
		req.logIn(user, () => {
			return res.json({ message: `ログイン成功！ Hello, ${user.username}` });
		});
	})(req, res);
});

// サインアップエンドポイント
app.get("/signup", (req, res) => {
	const { username, password } = req.query;
	if (!username || !password) {
		return res.status(400).json({
			message: "usernameとpasswordが必要です",
		});
	}

	// passwordをハッシュ化してDBに保存
	const newUser = { username, password: bcrypt.hashSync(password, 10) };
	userDB.push(newUser);

	// signUpが成功したのでログイン済みとしてsessionの追加
	req.logIn(newUser, () => {
		return res.json({ message: "サインアップ完了！", newUser });
	});
});

// ログアウトエンドポイント
app.get("/logout", (req, res) => {
	req.logout(() => {
		res.json({ message: "ログアウト成功" });
	});
});

// エンドポイントの説明
app.get("/", (req, res) => {
	res.json({
		endpoints: {
			"/users": "ユーザー一覧",
			"/login?username=<username>&password=<password>": "ログイン",
			"/signup?username=<username>&password=<password>": "サインアップ",
			"/logout": "ログアウト",
		},
	});
});

app.listen(3000, () => {
	console.log("Server running on http://localhost:3000");
});
