package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-redis/redis/v9"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	echopprof "github.com/hiko1129/echo-pprof"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	_ "github.com/newrelic/go-agent/_integrations/nrmysql"
	"github.com/newrelic/go-agent/v3/integrations/nrecho-v4"
	newrelic "github.com/newrelic/go-agent/v3/newrelic"
	"github.com/oklog/ulid/v2"
	"github.com/srinathgs/mysqlstore"
	"golang.org/x/crypto/bcrypt"
)

const (
	publicPath        = "./public"
	sessionCookieName = "listen80_session_golang"
	anonUserAccount   = "__"

	popularPlaylistCacheKey = "popular_playlist"
	favPlaylistCacheKey     = "favCache"
)

var (
	db           *sqlx.DB
	redisClient  *redis.Client
	sessionStore sessions.Store
	tr           = &renderer{templates: template.Must(template.ParseGlob("views/*.html"))}
	// for use ULID
	entropy = ulid.Monotonic(rand.New(rand.NewSource(time.Now().UnixNano())), 0)

	artistMap map[int]string
	banList   sync.Map
	userMap   sync.Map
	newRelic  *newrelic.Application
)

func getEnv(key string, defaultValue string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	return defaultValue
}

func connectDB() (*sqlx.DB, error) {
	config := mysql.NewConfig()
	config.Net = "tcp"
	config.Addr = getEnv("ISUCON_DB_HOST", "127.0.0.1") + ":" + getEnv("ISUCON_DB_PORT", "3306")
	config.User = getEnv("ISUCON_DB_USER", "isucon")
	config.Passwd = getEnv("ISUCON_DB_PASSWORD", "isucon")
	config.DBName = getEnv("ISUCON_DB_NAME", "isucon_listen80")
	config.ParseTime = true

	dsn := config.FormatDSN()
	db, err := sql.Open("nrmysql", dsn)
	if err != nil {
		log.Fatalf("failed to connect to DB: %s.", err.Error())
	}
	// defer db.Close()
	return sqlx.NewDb(db, "nrmysql"), nil
}

type renderer struct {
	templates *template.Template
}

func (t *renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func cacheControllPrivate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "private")
		return next(c)
	}
}

func main() {
	app, _err := newrelic.NewApplication(newrelic.ConfigAppName("kayac-isucon-2022"), newrelic.ConfigLicense("3c9c2bfaa615035f73eac0fc6a4cc1f506bdNRAL"))
	if _err != nil {
		fmt.Println(_err)
		os.Exit(1)
	}
	newRelic = app

	e := echo.New()
	e.Use(nrecho.Middleware(app))
	e.Debug = true
	e.Logger.SetLevel(log.DEBUG)

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(cacheControllPrivate)

	echopprof.Wrap(e)

	e.Renderer = tr
	e.Static("/assets", publicPath+"/assets")
	e.GET("/mypage", authRequiredPageHandler)
	e.GET("/playlist/:ulid/edit", authRequiredPageHandler)
	e.GET("/", authOptionalPageHandler)
	e.GET("/playlist/:ulid", authOptionalPageHandler)
	e.GET("/signup", authPageHandler)
	e.GET("/login", authPageHandler)

	e.POST("/api/signup", apiSignupHandler)
	e.POST("/api/login", apiLoginHandler)
	e.POST("/api/logout", apiLogoutHandler)
	e.GET("/api/recent_playlists", apiRecentPlaylistsHandler)
	e.GET("/api/popular_playlists", apiPopularPlaylistsHandler)
	e.GET("/api/playlists", apiPlaylistsHandler)
	e.GET("/api/playlist/:playlistUlid", apiPlaylistHandler)
	e.POST("/api/playlist/add", apiPlaylistAddHandler)
	e.POST("/api/playlist/:playlistUlid/update", apiPlaylistUpdateHandler)
	e.POST("/api/playlist/:playlistUlid/delete", apiPlaylistDeleteHandler)
	e.POST("/api/playlist/:playlistUlid/favorite", apiPlaylistFavoriteHandler)
	e.POST("/api/admin/user/ban", apiAdminUserBanHandler)

	e.POST("/initialize", initializeHandler)

	var err error
	db, err = connectDB()
	if err != nil {
		e.Logger.Fatalf("failed to connect db: %v", err)
		return
	}
	db.SetMaxOpenConns(10)
	defer db.Close()

	redisClient = redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	sessionStore, err = mysqlstore.NewMySQLStoreFromConnection(db.DB, "sessions_golang", "/", 86400, []byte("powawa"))
	if err != nil {
		e.Logger.Fatalf("failed to initialize session store: %v", err)
		return
	}

	port := getEnv("SERVER_APP_PORT", "3000")
	e.Logger.Infof("starting listen80 server on : %s ...", port)
	serverPort := fmt.Sprintf(":%s", port)
	e.Logger.Fatal(e.Start(serverPort))
}

func getSession(r *http.Request) (*sessions.Session, error) {
	session, err := sessionStore.Get(r, sessionCookieName)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func newSession(r *http.Request) (*sessions.Session, error) {
	session, err := sessionStore.New(r, sessionCookieName)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func errorResponse(c echo.Context, code int, message string) error {
	c.Logger().Debugf("error: status=%d, message=%s", code, message)

	body := BasicResponse{
		Result: false,
		Status: code,
		Error:  &message,
	}
	if code == 401 {
		sess, err := getSession(c.Request())
		if err != nil {
			return fmt.Errorf("error getSession at errorResponse: %w", err)
		}
		sess.Options.MaxAge = -1
		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return fmt.Errorf("error Save to session at errorResponse: %w", err)
		}
	}
	if err := c.JSON(code, body); err != nil {
		return fmt.Errorf("error returns JSON at errorResponse: %w", err)
	}
	return nil
}

func validateSession(c echo.Context) (*UserRow, bool, error) {
	sess, err := getSession(c.Request())
	if err != nil {
		return nil, false, fmt.Errorf("error getSession: %w", err)
	}
	_account, ok := sess.Values["user_account"]
	if !ok {
		return nil, false, nil
	}
	account := _account.(string)
	var user UserRow
	err = db.GetContext(
		c.Request().Context(),
		&user,
		"SELECT * FROM user where `account` = ?",
		account,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("error Get UserRow from db: %w", err)
	}
	if user.IsBan {
		return nil, false, nil
	}

	return &user, true, nil
}

func generatePasswordHash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 11)
	if err != nil {
		return "", fmt.Errorf("error bcrypt.GenerateFromPassword: %w", err)
	}
	return string(hashed), nil
}

func comparePasswordHash(newPassword, passwordHash string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, fmt.Errorf("error bcrypt.CompateHashAndPassword: %w", err)
	}
	return true, nil
}

// 認証必須ページ

type TemplateParams struct {
	LoggedIn    bool
	Params      map[string]string
	DisplayName string
	UserAccount string
}

var authRequiredPages = map[string]string{
	"/mypage":              "mypage.html",
	"/playlist/:ulid/edit": "playlist_edit.html",
}

func authRequiredPageHandler(c echo.Context) error {
	user, ok, err := validateSession(c)
	if err != nil {
		return fmt.Errorf("error %s at authRequired: %w", c.Path(), err)
	}
	if !ok || user == nil {
		c.Redirect(http.StatusFound, "/")
		return nil
	}
	page := authRequiredPages[c.Path()]

	return c.Render(http.StatusOK, page, &TemplateParams{
		LoggedIn: true,
		Params: map[string]string{
			"ulid": c.Param("ulid"),
		},
		DisplayName: user.DisplayName,
		UserAccount: user.Account,
	})
}

var authOptionalPages = map[string]string{
	"/":               "top.html",
	"/playlist/:ulid": "playlist.html",
}

func authOptionalPageHandler(c echo.Context) error {
	user, ok, err := validateSession(c)
	if err != nil {
		return fmt.Errorf("error %s at authRequired: %w", c.Path(), err)
	}
	if user != nil && user.IsBan {
		return errorResponse(c, 401, "failed to fetch user (no such user)")
	}

	var displayName, account string
	if user != nil {
		displayName = user.DisplayName
		account = user.Account
	}
	page := authOptionalPages[c.Path()]
	return c.Render(http.StatusOK, page, &TemplateParams{
		LoggedIn: ok,
		Params: map[string]string{
			"ulid": c.Param("ulid"),
		},
		DisplayName: displayName,
		UserAccount: account,
	})
}

var authPages = map[string]string{
	"/signup": "signup.html",
	"/login":  "login.html",
}

func authPageHandler(c echo.Context) error {
	page := authPages[c.Path()]
	return c.Render(http.StatusOK, page, &TemplateParams{
		LoggedIn: false,
	})
}

// DBにアクセスして結果を引いてくる関数

func getPlaylistByULID(ctx context.Context, db connOrTx, playlistULID string) (*PlaylistRow, error) {
	var row PlaylistRow
	if err := db.GetContext(ctx, &row, "SELECT * FROM playlist WHERE `ulid` = ?", playlistULID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error Get playlist by ulid=%s: %w", playlistULID, err)
	}
	return &row, nil
}

func getPlaylistByIDs(ctx context.Context, db connOrTx, ids []int) ([]PlaylistRow, error) {
	sql := `SELECT * FROM playlist WHERE id IN (?) and is_public = 1`
	sql, params, err := sqlx.In(sql, ids)
	if err != nil {
		return nil, fmt.Errorf("sqlx.In ulids=%v: %w", ids, err)
	}
	var row []PlaylistRow
	if err := db.SelectContext(ctx, &row, sql, params...); err != nil {
		return nil, fmt.Errorf("error Get song by ulids=%v: %w", ids, err)
	}
	return row, nil
}

func getPlaylistByID(ctx context.Context, db connOrTx, playlistID int) (*PlaylistRow, error) {
	var row PlaylistRow
	if err := db.GetContext(ctx, &row, "SELECT * FROM playlist WHERE `id` = ?", playlistID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error Get playlist by id=%d: %w", playlistID, err)
	}
	return &row, nil
}

type connOrTx interface {
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

func getSongsByULIDs(ctx context.Context, db connOrTx, songULIDs []string) ([]SongRow, error) {
	sql := `SELECT * FROM song WHERE ulid IN (?)`
	sql, params, err := sqlx.In(sql, songULIDs)
	if err != nil {
		return nil, fmt.Errorf("sqlx.In ulids=%s: %w", songULIDs, err)
	}
	var row []SongRow
	if err := db.SelectContext(ctx, &row, sql, params...); err != nil {
		return nil, fmt.Errorf("error Get song by ulids=%s: %w", songULIDs, err)
	}
	return row, nil
}

func isFavoritedBy(ctx context.Context, db connOrTx, userAccount string, playlistID int) (bool, error) {
	var count int
	if err := db.GetContext(
		ctx,
		&count,
		"SELECT COUNT(*) AS cnt FROM playlist_favorite where favorite_user_account = ? AND playlist_id = ?",
		userAccount, playlistID,
	); err != nil {
		return false, fmt.Errorf(
			"error Get count of playlist_favorite by favorite_user_account=%s, playlist_id=%d: %w",
			userAccount, playlistID, err,
		)
	}
	return count > 0, nil
}

func getFavoritePlayListsByLoginUsers(ctx context.Context, db connOrTx, userAccount string) ([]PlaylistFavoriteRow, error) {
	var re []PlaylistFavoriteRow
	if err := db.SelectContext(
		ctx,
		&re,
		"SELECT * FROM playlist_favorite where favorite_user_account = ?",
		userAccount,
	); err != nil {
		return nil, fmt.Errorf(
			"error Get count of playlist_favorite by favorite_user_account=%s, %w",
			userAccount, err,
		)
	}
	return re, nil
}

func getFavoritesCountByPlaylistID(ctx context.Context, db connOrTx, playlistID int) (int, error) {
	var count int
	if err := db.GetContext(
		ctx,
		&count,
		"SELECT COUNT(*) AS cnt FROM playlist_favorite where playlist_id = ?",
		playlistID,
	); err != nil {
		return 0, fmt.Errorf(
			"error Get count of playlist_favorite by playlist_id=%d: %w",
			playlistID, err,
		)
	}
	return count, nil
}

func getSongsCountByPlaylistID(ctx context.Context, db connOrTx, playlistID int) (int, error) {
	var count int
	if err := db.GetContext(
		ctx,
		&count,
		"SELECT COUNT(*) AS cnt FROM playlist_song where playlist_id = ?",
		playlistID,
	); err != nil {
		return 0, fmt.Errorf(
			"error Get count of playlist_song by playlist_id=%d: %w",
			playlistID, err,
		)
	}
	return count, nil
}

func getRecentPlaylistSummaries(ctx context.Context, db connOrTx, userAccount string) ([]Playlist, error) {
	if userAccount == anonUserAccount {
		return getRecentPlaylistSummariesByNonAuthUser(ctx, db)
	}

	return getRecentPlaylistSummariesByUser(ctx, db, userAccount)
}

// login user の list
func getRecentPlaylistSummariesByUser(ctx context.Context, db connOrTx, userAccount string) ([]Playlist, error) {
	var allPlaylists []PlaylistRow
	uids := make([]string, 0, 1000)
	banList.Range(func(key any, v any) bool {
		uids = append(uids, key.(string))
		return true
	})
	if len(uids) > 0 {
		sql := `SELECT * FROM playlist where is_public = 1 and user_account not in (?) ORDER BY created_at DESC limit 100`
		sql, params, err := sqlx.In(sql, uids)
		if err != nil {
			return nil, fmt.Errorf("sqlx.In ids=%v: %w", uids, err)
		}
		if err := db.SelectContext(ctx, &allPlaylists, sql, params...); err != nil {
			return nil, fmt.Errorf("error Get song by ids=%v: %w", uids, err)
		}
	} else {
		sql := `SELECT * FROM playlist where is_public = 1 ORDER BY created_at DESC limit 100`
		if err := db.SelectContext(ctx, &allPlaylists, sql); err != nil {
			return nil, fmt.Errorf("error Get song by ids=%v: %w", uids, err)
		}
	}

	if len(allPlaylists) == 0 {
		return nil, nil
	}

	favs, err := getFavoritePlayListsByLoginUsers(ctx, db, userAccount)
	if err != nil {
		return nil, err
	}
	favMap := map[int]struct{}{}
	for _, item := range favs {
		favMap[item.PlaylistID] = struct{}{}
	}

	pids := make([]int, 0, 100)
	for _, item := range allPlaylists {
		pids = append(pids, item.ID)
	}
	sMap, err := getSongCountMap(ctx, db, pids)
	if err != nil {
		return nil, err
	}

	playlists := make([]Playlist, 0, len(allPlaylists))
	for _, playlist := range allPlaylists {
		favCount, err := getFavCount(ctx, db, playlist.ID)
		if err != nil {
			return nil, err
		}

		_, isFavorited := favMap[playlist.ID]
		_user, ok := userMap.Load(playlist.UserAccount)
		if !ok {
			continue
		}
		user := _user.(*UserRow)

		playlists = append(playlists, Playlist{
			ULID:            playlist.ULID,
			Name:            playlist.Name,
			UserDisplayName: user.DisplayName,
			UserAccount:     user.Account,
			SongCount:       sMap[playlist.ID],
			FavoriteCount:   favCount,
			IsFavorited:     isFavorited,
			IsPublic:        playlist.IsPublic,
			CreatedAt:       playlist.CreatedAt,
			UpdatedAt:       playlist.UpdatedAt,
		})
	}
	return playlists, nil
}

// no login user の list
func getRecentPlaylistSummariesByNonAuthUser(ctx context.Context, db connOrTx) ([]Playlist, error) {
	var allPlaylists []PlaylistRow
	uids := make([]string, 0, 1000)
	banList.Range(func(key any, v any) bool {
		uids = append(uids, key.(string))
		return true
	})
	if len(uids) > 0 {
		ctx := newrelic.NewContext(ctx, newrelic.FromContext(ctx))
		sql := `SELECT * FROM playlist where is_public = 1 and user_account not in (?) ORDER BY created_at DESC limit 100`
		sql, params, err := sqlx.In(sql, uids)
		if err != nil {
			return nil, fmt.Errorf("sqlx.In ids=%v: %w", uids, err)
		}
		if err := db.SelectContext(ctx, &allPlaylists, sql, params...); err != nil {
			return nil, fmt.Errorf("error Get song by ids=%v: %w", uids, err)
		}
	} else {
		ctx := newrelic.NewContext(ctx, newrelic.FromContext(ctx))
		sql := `SELECT * FROM playlist where is_public = 1 ORDER BY created_at DESC limit 100`
		if err := db.SelectContext(ctx, &allPlaylists, sql); err != nil {
			return nil, fmt.Errorf("error Get song by ids=%v: %w", uids, err)
		}
	}
	// if err := db.SelectContext(
	// 	ctx,
	// 	&allPlaylists,
	// 	"SELECT * FROM playlist where is_public = ? and user_account in (SELECT account FROM user WHERE is_ban = ?) ORDER BY created_at DESC limit 100",
	// 	true,
	// 	false,
	// ); err != nil {
	// 	return nil, fmt.Errorf(
	// 		"error Select playlist by is_public=true: %w",
	// 		err,
	// 	)
	// }
	if len(allPlaylists) == 0 {
		return nil, nil
	}

	pids := make([]int, 0, 100)
	for _, item := range allPlaylists {
		pids = append(pids, item.ID)
	}
	sMap, err := getSongCountMap(ctx, db, pids)
	if err != nil {
		return nil, err
	}

	playlists := make([]Playlist, 0, len(allPlaylists))
	for _, playlist := range allPlaylists {
		favCount, err := getFavCount(ctx, db, playlist.ID)
		if err != nil {
			return nil, err
		}

		_user, ok := userMap.Load(playlist.UserAccount)
		if !ok {
			continue
		}
		user := _user.(*UserRow)

		playlists = append(playlists, Playlist{
			ULID:            playlist.ULID,
			Name:            playlist.Name,
			UserDisplayName: user.DisplayName,
			UserAccount:     user.Account,
			SongCount:       sMap[playlist.ID],
			FavoriteCount:   favCount,
			IsFavorited:     false,
			IsPublic:        playlist.IsPublic,
			CreatedAt:       playlist.CreatedAt,
			UpdatedAt:       playlist.UpdatedAt,
		})
	}
	return playlists, nil
}

func getFavCount(ctx context.Context, db connOrTx, playlistID int) (int, error) {
	var favCount int
	re, err := redisClient.ZScore(ctx, favPlaylistCacheKey, fmt.Sprintf("%v", playlistID)).Result()
	if err == nil {
		favCount = int(re)
	} else {
		favoriteCount, err := getFavoritesCountByPlaylistID(ctx, db, playlistID)
		if err != nil {
			return favCount, fmt.Errorf("error getFavoritesCountByPlaylistID: %w", err)
		}
		favCount = favoriteCount
	}
	return favCount, nil
}

func getSongCountMap(ctx context.Context, db connOrTx, pids []int) (map[int]int, error) {
	ctx = newrelic.NewContext(ctx, newrelic.FromContext(ctx))
	var songCount []struct {
		PlaylistID int `db:"playlist_id"`
		SongCount  int `db:"song_count"`
	}
	sql := `SELECT playlist_id, count(*) AS song_count FROM playlist_song where playlist_id in (?) GROUP BY playlist_id ORDER BY count(*) DESC`
	sql, params, err := sqlx.In(sql, pids)
	if err != nil {
		return nil, fmt.Errorf("sqlx.In ids=%v: %w", pids, err)
	}
	if err := db.SelectContext(ctx, &songCount, sql, params...); err != nil {
		return nil, fmt.Errorf("error Get song by ids=%v: %w", pids, err)
	}
	sMap := map[int]int{}
	for _, item := range songCount {
		sMap[item.PlaylistID] = item.SongCount
	}
	return sMap, nil
}

func getPopularPlaylistSummaries(ctx context.Context, db connOrTx, userAccount string) ([]Playlist, error) {
	txn := newrelic.FromContext(ctx)
	_1 := txn.StartSegment("getFavoritePlayListsByLoginUsers")
	s, e := int64(0), int64(250)
	favs, err := getFavoritePlayListsByLoginUsers(ctx, db, userAccount)
	if err != nil {
		return nil, err
	}
	_1.End()
	favMap := map[int]struct{}{}
	for _, item := range favs {
		favMap[item.PlaylistID] = struct{}{}
	}
	defer txn.StartSegment("makePopularPlaylist").End()
	for {
		// cache があるとき
		strs, err := redisClient.ZRevRangeWithScores(ctx, popularPlaylistCacheKey, s, e).Result()
		if err != nil {
			return nil, fmt.Errorf(
				"error redisClient.ZRange: %w",
				err,
			)
		}

		pids := make([]int, 0, 100)
		for _, item := range strs {
			pid := item.Member.(string)
			_pid, _ := strconv.Atoi(pid)
			pids = append(pids, _pid)
		}
		sMap, err := getSongCountMap(ctx, db, pids)
		if err != nil {
			return nil, err
		}
		playlists := make([]Playlist, 0, 100)
		ps, err := getPlaylistByIDs(ctx, db, pids)
		if err != nil {
			return nil, err
		}
		for _, playlist := range ps {
			if _, ok := banList.Load(playlist.UserAccount); ok {
				continue
			}
			_user, ok := userMap.Load(playlist.UserAccount)
			if !ok {
				continue
			}
			user := _user.(*UserRow)

			favCount, err := getFavCount(ctx, db, playlist.ID)
			if err != nil {
				return nil, err
			}

			pitem := Playlist{
				ULID:            playlist.ULID,
				Name:            playlist.Name,
				UserDisplayName: user.DisplayName,
				UserAccount:     user.Account,
				SongCount:       sMap[playlist.ID],
				FavoriteCount:   favCount,
				IsPublic:        playlist.IsPublic,
				CreatedAt:       playlist.CreatedAt,
				UpdatedAt:       playlist.UpdatedAt,
			}

			if userAccount != anonUserAccount {
				_, isFavorited := favMap[playlist.ID]
				pitem.IsFavorited = isFavorited
			}

			playlists = append(playlists, pitem)
			if len(playlists) >= 100 {
				sort.Slice(playlists, func(i, j int) bool {
					return playlists[i].FavoriteCount > playlists[j].FavoriteCount
				})
				return playlists, nil
			}
		}
		s = e
		e += 250
	}
}

func getCreatedPlaylistSummariesByUserAccount(ctx context.Context, db connOrTx, userAccount string) ([]Playlist, error) {
	var playlists []PlaylistRow
	if err := db.SelectContext(
		ctx,
		&playlists,
		"SELECT * FROM playlist where user_account = ? ORDER BY created_at DESC LIMIT 100",
		userAccount,
	); err != nil {
		return nil, fmt.Errorf(
			"error Select playlist by user_account=%s: %w",
			userAccount, err,
		)
	}
	if len(playlists) == 0 {
		return nil, nil
	}

	user, err := getUserByAccount(ctx, db, userAccount)
	if err != nil {
		return nil, fmt.Errorf("error getUserByAccount: %w", err)
	}
	if user == nil || user.IsBan {
		return nil, nil
	}

	favs, err := getFavoritePlayListsByLoginUsers(ctx, db, userAccount)
	if err != nil {
		return nil, err
	}
	favMap := map[int]struct{}{}
	for _, item := range favs {
		favMap[item.PlaylistID] = struct{}{}
	}

	results := make([]Playlist, 0, len(playlists))
	for _, row := range playlists {
		songCount, err := getSongsCountByPlaylistID(ctx, db, row.ID)
		if err != nil {
			return nil, fmt.Errorf("error getSongsCountByPlaylistID: %w", err)
		}
		favCount, err := getFavCount(ctx, db, row.ID)
		if err != nil {
			return nil, err
		}

		_, isFavorited := favMap[row.ID]

		results = append(results, Playlist{
			ULID:            row.ULID,
			Name:            row.Name,
			UserDisplayName: user.DisplayName,
			UserAccount:     user.Account,
			SongCount:       songCount,
			FavoriteCount:   favCount,
			IsFavorited:     isFavorited,
			IsPublic:        row.IsPublic,
			CreatedAt:       row.CreatedAt,
			UpdatedAt:       row.UpdatedAt,
		})
	}

	return results, nil
}

func getFavoritedPlaylistSummariesByUserAccount(ctx context.Context, db connOrTx, userAccount string) ([]Playlist, error) {
	var playlistFavorites []PlaylistFavoriteRow
	if err := db.SelectContext(
		ctx,
		&playlistFavorites,
		"SELECT * FROM playlist_favorite where favorite_user_account = ? ORDER BY created_at DESC",
		userAccount,
	); err != nil {
		return nil, fmt.Errorf(
			"error Select playlist_favorite by user_account=%s: %w",
			userAccount, err,
		)
	}

	favs, err := getFavoritePlayListsByLoginUsers(ctx, db, userAccount)
	if err != nil {
		return nil, err
	}
	favMap := map[int]struct{}{}
	for _, item := range favs {
		favMap[item.PlaylistID] = struct{}{}
	}

	playlists := make([]Playlist, 0, 100)
	for _, fav := range playlistFavorites {
		playlist, err := getPlaylistByID(ctx, db, fav.PlaylistID)
		if err != nil {
			return nil, fmt.Errorf("error getPlaylistByID: %w", err)
		}
		// 非公開は除外する
		if playlist == nil || !playlist.IsPublic {
			continue
		}
		if _, ok := banList.Load(playlist.UserAccount); ok {
			continue
		}
		_user, ok := userMap.Load(playlist.UserAccount)
		if !ok {
			continue
		}
		user := _user.(*UserRow)

		songCount, err := getSongsCountByPlaylistID(ctx, db, playlist.ID)
		if err != nil {
			return nil, fmt.Errorf("error getSongsCountByPlaylistID: %w", err)
		}
		favCount, err := getFavCount(ctx, db, playlist.ID)
		if err != nil {
			return nil, err
		}
		_, isFavorited := favMap[playlist.ID]
		playlists = append(playlists, Playlist{
			ULID:            playlist.ULID,
			Name:            playlist.Name,
			UserDisplayName: user.DisplayName,
			UserAccount:     user.Account,
			SongCount:       songCount,
			FavoriteCount:   favCount,
			IsFavorited:     isFavorited,
			IsPublic:        playlist.IsPublic,
			CreatedAt:       playlist.CreatedAt,
			UpdatedAt:       playlist.UpdatedAt,
		})
		if len(playlists) >= 100 {
			break
		}
	}

	return playlists, nil
}

func getPlaylistDetailByPlaylistULID(ctx context.Context, db connOrTx, playlistULID string, viewerUserAccount *string) (*PlaylistDetail, error) {
	playlist, err := getPlaylistByULID(ctx, db, playlistULID)
	if err != nil {
		return nil, fmt.Errorf("error getPlaylistByULID: %w", err)
	}
	if playlist == nil {
		return nil, nil
	}

	user, err := getUserByAccount(ctx, db, playlist.UserAccount)
	if err != nil {
		return nil, fmt.Errorf("error getUserByAccount: %w", err)
	}
	if user == nil || user.IsBan {
		return nil, nil
	}

	favCount, err := getFavCount(ctx, db, playlist.ID)
	if err != nil {
		return nil, err
	}

	var isFavorited bool
	if viewerUserAccount != nil {
		var err error
		isFavorited, err = isFavoritedBy(ctx, db, *viewerUserAccount, playlist.ID)
		if err != nil {
			return nil, fmt.Errorf("error isFavoritedBy: %w", err)
		}
	}

	var resPlaylistSongs []PlaylistSongRow
	if err := db.SelectContext(
		ctx,
		&resPlaylistSongs,
		"SELECT * FROM playlist_song WHERE playlist_id = ?",
		playlist.ID,
	); err != nil {
		return nil, fmt.Errorf(
			"error Select playlist_song by playlist_id=%d: %w",
			playlist.ID, err,
		)
	}

	songs := make([]Song, 0, len(resPlaylistSongs))
	for _, row := range resPlaylistSongs {
		var song SongRow
		if err := db.GetContext(
			ctx,
			&song,
			"SELECT * FROM song WHERE id = ?",
			row.SongID,
		); err != nil {
			return nil, fmt.Errorf("error Get song by id=%d: %w", row.SongID, err)
		}

		songs = append(songs, Song{
			ULID:        song.ULID,
			Title:       song.Title,
			Artist:      artistMap[song.ArtistID],
			Album:       song.Album,
			TrackNumber: song.TrackNumber,
			IsPublic:    song.IsPublic,
		})
	}

	return &PlaylistDetail{
		Playlist: &Playlist{
			ULID:            playlist.ULID,
			Name:            playlist.Name,
			UserDisplayName: user.DisplayName,
			UserAccount:     user.Account,
			SongCount:       len(songs),
			FavoriteCount:   favCount,
			IsFavorited:     isFavorited,
			IsPublic:        playlist.IsPublic,
			CreatedAt:       playlist.CreatedAt,
			UpdatedAt:       playlist.UpdatedAt,
		},
		Songs: songs,
	}, nil
}

func getPlaylistFavoritesByPlaylistIDAndUserAccount(ctx context.Context, db connOrTx, playlistID int, favoriteUserAccount string) (*PlaylistFavoriteRow, error) {
	var result []PlaylistFavoriteRow
	if err := db.SelectContext(
		ctx,
		&result,
		"SELECT * FROM playlist_favorite WHERE `playlist_id` = ? AND `favorite_user_account` = ?",
		playlistID,
		favoriteUserAccount,
	); err != nil {
		return nil, fmt.Errorf(
			"error Select playlist_favorite by playlist_id=%d, favorite_user_account=%s: %w",
			playlistID, favoriteUserAccount, err,
		)
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &result[0], nil
}

func getUserByAccount(ctx context.Context, db connOrTx, account string) (*UserRow, error) {
	var result UserRow
	if err := db.GetContext(
		ctx,
		&result,
		"SELECT * FROM user WHERE `account` = ?",
		account,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf(
			"error Get user by account=%s: %w",
			account, err,
		)
	}
	return &result, nil
}

func insertPlaylistFavorite(ctx context.Context, db connOrTx, playlistID int, favoriteUserAccount string, createdAt time.Time) error {
	if _, err := db.ExecContext(
		ctx,
		"INSERT INTO playlist_favorite (`playlist_id`, `favorite_user_account`, `created_at`) VALUES (?, ?, ?)",
		playlistID, favoriteUserAccount, createdAt,
	); err != nil {
		return fmt.Errorf(
			"error Insert playlist_favorite by playlist_id=%d, favorite_user_account=%s, created_at=%s: %w",
			playlistID, favoriteUserAccount, createdAt, err,
		)
	}
	return nil
}

// POST /api/signup

func apiSignupHandler(c echo.Context) error {
	var signupRequest SignupRequest
	if err := c.Bind(&signupRequest); err != nil {
		c.Logger().Errorf("error Bind request to SignupRequest: %s", err)
		return errorResponse(c, 500, "failed to signup")
	}
	userAccount := signupRequest.UserAccount
	password := signupRequest.Password
	displayName := signupRequest.DisplayName

	// validation
	if userAccount == "" || len(userAccount) < 4 || 191 < len(userAccount) {
		return errorResponse(c, 400, "bad user_account")
	}
	if matched, _ := regexp.MatchString(`[^a-zA-Z0-9\-_]`, userAccount); matched {
		return errorResponse(c, 400, "bad user_account")
	}
	if password == "" || len(password) < 8 || 64 < len(password) {
		return errorResponse(c, 400, "bad password")
	}
	if matched, _ := regexp.MatchString(`[^a-zA-Z0-9\-_]`, password); matched {
		return errorResponse(c, 400, "bad password")
	}
	if displayName == "" || utf8.RuneCountInString(displayName) < 2 || 24 < utf8.RuneCountInString(displayName) {
		return errorResponse(c, 400, "bad display_name")
	}

	// password hashを作る
	passwordHash, err := generatePasswordHash(password)
	if err != nil {
		c.Logger().Errorf("error generatePasswordHash: %s", err)
		return errorResponse(c, 500, "failed to signup")
	}

	// default value
	isBan := false
	signupTimestamp := time.Now()

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "failed to signup")
	}
	defer conn.Close()

	if _, err := conn.ExecContext(
		ctx,
		"INSERT INTO user (`account`, `display_name`, `password_hash`, `is_ban`, `created_at`, `last_logined_at`) VALUES (?, ?, ?, ?, ?, ?)",
		userAccount, displayName, passwordHash, isBan, signupTimestamp, signupTimestamp,
	); err != nil {
		// handling a "Duplicate entry"
		if merr, ok := err.(*mysql.MySQLError); ok && merr.Number == 1062 {
			return errorResponse(c, 400, "account already exist")
		}
		return fmt.Errorf(
			"error Insert user by user_account=%s, display_name=%s, password_hash=%s, is_ban=%t, created_at=%s, updated_at=%s: %w",

			userAccount, displayName, passwordHash, isBan, signupTimestamp, signupTimestamp, err,
		)
	}

	sess, err := newSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error newSession: %s", err)
		return errorResponse(c, 500, "failed to signup")
	}
	sess.Values["user_account"] = userAccount
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		c.Logger().Errorf("error Save to session: %s", err)
		return errorResponse(c, 500, "failed to signup")
	}

	userMap.Store(userAccount, &UserRow{
		Account:     userAccount,
		DisplayName: displayName,
	})

	body := BasicResponse{
		Result: true,
		Status: 200,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "failed to signup")
	}

	return nil
}

// POST /api/login

func apiLoginHandler(c echo.Context) error {
	var loginRequest LoginRequest
	if err := c.Bind(&loginRequest); err != nil {
		c.Logger().Errorf("error Bind request to LoginRequest: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}
	userAccount := loginRequest.UserAccount
	password := loginRequest.Password

	// validation
	if userAccount == "" || len(userAccount) < 4 || 191 < len(userAccount) {
		return errorResponse(c, 400, "bad user_account")
	}
	if matched, _ := regexp.MatchString(`[^a-zA-Z0-9\-_]`, userAccount); matched {
		return errorResponse(c, 400, "bad user_account")
	}
	if password == "" || len(password) < 8 || 64 < len(password) {
		return errorResponse(c, 400, "bad password")
	}
	if matched, _ := regexp.MatchString(`[^a-zA-Z0-9\-_]`, password); matched {
		return errorResponse(c, 400, "bad password")
	}

	// password check
	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}
	defer conn.Close()

	user, err := getUserByAccount(ctx, conn, userAccount)
	if err != nil {
		c.Logger().Errorf("error getUserByAccount: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}
	if user == nil || user.IsBan {
		// ユーザがいないかbanされている
		return errorResponse(c, 401, "failed to login (no such user)")
	}

	matched, err := comparePasswordHash(password, user.PasswordHash)
	if err != nil {
		c.Logger().Errorf("error comparePasswordHash: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}
	if !matched {
		// wrong password
		return errorResponse(c, 401, "failed to login (wrong password)")
	}

	now := time.Now()
	if _, err := conn.ExecContext(
		ctx,
		"UPDATE user SET last_logined_at = ? WHERE account = ?",
		now, user.Account,
	); err != nil {
		c.Logger().Errorf("error Update user by last_logined_at=%s, account=%s: %s", now, user.Account, err)
		return errorResponse(c, 500, "failed to login (server error)")
	}

	sess, err := newSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error newSession: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}
	sess.Values["user_account"] = userAccount
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		c.Logger().Errorf("error Save to session: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}

	body := BasicResponse{
		Result: true,
		Status: 200,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "failed to login (server error)")
	}

	return nil
}

// POST /api/logout

func apiLogoutHandler(c echo.Context) error {
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "failed to logout (server error)")
	}
	sess.Options.MaxAge = -1
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		c.Logger().Errorf("error Save session:  %s", err)
		return errorResponse(c, 500, "failed to logout (server error)")
	}

	body := BasicResponse{
		Result: true,
		Status: 200,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "failed to logout (server error)")
	}

	return nil
}

// GET /api/recent_playlists

func apiRecentPlaylistsHandler(c echo.Context) error {
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	userAccount := anonUserAccount
	_account, ok := sess.Values["user_account"]
	if ok {
		userAccount = _account.(string)
	}

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	playlists, err := getRecentPlaylistSummaries(ctx, conn, userAccount)
	if err != nil {
		c.Logger().Errorf("error getRecentPlaylistSummaries: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	body := GetRecentPlaylistsResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		Playlists: playlists,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// GET /api/popular_playlists

func apiPopularPlaylistsHandler(c echo.Context) error {
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	userAccount := anonUserAccount
	_account, ok := sess.Values["user_account"]
	if ok {
		userAccount = _account.(string)
	}

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	// トランザクションを使わないとfav数の順番が狂うことがある
	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		c.Logger().Errorf("error conn.BeginTxx: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	playlists, err := getPopularPlaylistSummaries(ctx, tx, userAccount)
	if err != nil {
		tx.Rollback()
		c.Logger().Errorf("error getPopularPlaylistSummaries: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	tx.Commit()

	body := GetRecentPlaylistsResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		Playlists: playlists,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// GET /api/playlists

func apiPlaylistsHandler(c echo.Context) error {
	_, valid, err := validateSession(c)
	if err != nil {
		c.Logger().Errorf("error validateSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if !valid {
		return errorResponse(c, 401, "login required")
	}
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	_account := sess.Values["user_account"]
	userAccount := _account.(string)

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	createdPlaylists, err := getCreatedPlaylistSummariesByUserAccount(ctx, conn, userAccount)
	if err != nil {
		c.Logger().Errorf("error getCreatedPlaylistSummariesByUserAccount: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if createdPlaylists == nil {
		createdPlaylists = []Playlist{}
	}
	favoritedPlaylists, err := getFavoritedPlaylistSummariesByUserAccount(ctx, conn, userAccount)
	if err != nil {
		c.Logger().Errorf("error getFavoritedPlaylistSummariesByUserAccount: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	body := GetPlaylistsResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		CreatedPlaylists:   createdPlaylists,
		FavoritedPlaylists: favoritedPlaylists,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// GET /api/playlist/{:playlistUlid}

func apiPlaylistHandler(c echo.Context) error {
	// ログインは不要
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	userAccount := anonUserAccount
	_account, ok := sess.Values["user_account"]
	if ok {
		userAccount = _account.(string)
	}
	playlistULID := c.Param("playlistUlid")

	// validation
	if playlistULID == "" {
		return errorResponse(c, 400, "bad playlist ulid")
	}
	if matched, _ := regexp.MatchString("[^a-zA-Z0-9]", playlistULID); matched {
		return errorResponse(c, 400, "bad playlist ulid")
	}

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	playlist, err := getPlaylistByULID(ctx, conn, playlistULID)
	if err != nil {
		c.Logger().Errorf("error getPlaylistByULID:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlist == nil {
		return errorResponse(c, 404, "playlist not found")
	}

	// 作成者が自分ではない、privateなプレイリストは見れない
	if playlist.UserAccount != userAccount && !playlist.IsPublic {
		return errorResponse(c, 404, "playlist not found")
	}

	playlistDetails, err := getPlaylistDetailByPlaylistULID(ctx, conn, playlist.ULID, &userAccount)
	if err != nil {
		c.Logger().Errorf("error getPlaylistDetailByPlaylistULID:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlistDetails == nil {
		return errorResponse(c, 404, "playlist not found")
	}

	body := SinglePlaylistResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		Playlist: *playlistDetails,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// POST /api/playlist/add

func apiPlaylistAddHandler(c echo.Context) error {
	_, valid, err := validateSession(c)
	if err != nil {
		c.Logger().Errorf("error validateSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if !valid {
		return errorResponse(c, 401, "login required")
	}

	var addPlaylistRequest AddPlaylistRequest
	if err := c.Bind(&addPlaylistRequest); err != nil {
		c.Logger().Errorf("error Bind request to AddPlaylistRequest: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	name := addPlaylistRequest.Name
	if name == "" || utf8.RuneCountInString(name) < 2 || 191 < utf8.RuneCountInString(name) {
		return errorResponse(c, 400, "invalid name")
	}

	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	_account := sess.Values["user_account"]
	userAccount := _account.(string)
	createTimestamp := time.Now()
	playlistULID, err := ulid.New(ulid.Timestamp(createTimestamp), entropy)
	if err != nil {
		c.Logger().Errorf("error ulid.New: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	if _, err := conn.ExecContext(
		ctx,
		"INSERT INTO playlist (`ulid`, `name`, `user_account`, `is_public`, `created_at`, `updated_at`) VALUES (?, ?, ?, ?, ?, ?)",
		playlistULID.String(), name, userAccount, false, createTimestamp, createTimestamp, // 作成時は非公開
	); err != nil {
		c.Logger().Errorf(
			"error Insert playlist by ulid=%s, name=%s, user_account=%s, is_public=%t, created_at=%s, updated_at=%s: %s",
			playlistULID, name, userAccount, false, createTimestamp, createTimestamp,
		)
		return errorResponse(c, 500, "internal server error")
	}

	body := AddPlaylistResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		PlaylistULID: playlistULID.String(),
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// POST /api/playlist/update

// Todo: songs の hash 持っておいて、前回と一緒だったら更新しないようにする
func apiPlaylistUpdateHandler(c echo.Context) error {
	_, valid, err := validateSession(c)
	if err != nil {
		c.Logger().Errorf("error validateSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if !valid {
		return errorResponse(c, 401, "login required")
	}
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	_account := sess.Values["user_account"]
	userAccount := _account.(string)

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	playlistULID := c.Param("playlistUlid")
	playlist, err := getPlaylistByULID(ctx, conn, playlistULID)
	if err != nil {
		c.Logger().Errorf("error getPlaylistByULID: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlist == nil {
		return errorResponse(c, 404, "playlist not found")
	}
	if playlist.UserAccount != userAccount {
		// 権限エラーだが、URI上のパラメータが不正なので404を返す
		return errorResponse(c, 404, "playlist not found")
	}

	var updatePlaylistRequest UpdatePlaylistRequest
	if err := c.Bind(&updatePlaylistRequest); err != nil {
		c.Logger().Errorf("error Bind request to UpdatePlaylistRequest: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	name := updatePlaylistRequest.Name
	songULIDs := updatePlaylistRequest.SongULIDs
	isPublic := updatePlaylistRequest.IsPublic
	// validation
	if matched, _ := regexp.MatchString("[^a-zA-Z0-9]", playlistULID); matched {
		return errorResponse(c, 404, "bad playlist ulid")
	}
	// 必須パラメータをチェック
	if name == nil || *name == "" || songULIDs == nil {
		return errorResponse(c, 400, "name, song_ulids and is_public is required")
	}
	// nameは2文字以上191文字以内
	if utf8.RuneCountInString(*name) < 2 || 191 < utf8.RuneCountInString(*name) {
		return errorResponse(c, 400, "invalid name")
	}
	// 曲数は最大80曲
	if 80 < len(songULIDs) {
		return errorResponse(c, 400, "invalid song_ulids")
	}
	// 曲は重複してはいけない
	songULIDsSet := make(map[string]struct{}, len(songULIDs))
	for _, songULID := range songULIDs {
		songULIDsSet[songULID] = struct{}{}
	}
	if len(songULIDsSet) != len(songULIDs) {
		return errorResponse(c, 400, "invalid song_ulids")
	}

	updatedTimestamp := time.Now()

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		c.Logger().Errorf("error conn.BeginTxx: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	// name, is_publicの更新
	if _, err := tx.ExecContext(
		ctx,
		"UPDATE playlist SET name = ?, is_public = ?, `updated_at` = ? WHERE `ulid` = ?",
		name, isPublic, updatedTimestamp, playlist.ULID,
	); err != nil {
		tx.Rollback()
		c.Logger().Errorf(
			"error Update playlist by name=%s, is_public=%t, updated_at=%s, ulid=%s: %s",
			name, isPublic, updatedTimestamp, playlist.ULID, err,
		)
		return errorResponse(c, 500, "internal server error")
	}

	cnt, err := getSongsCountByPlaylistID(ctx, tx, playlist.ID)
	if err != nil {
		tx.Rollback()
		c.Logger().Errorf("getSongsCountByPlaylistID: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if 0 < cnt {
		// songsを削除→新しいものを入れる
		if _, err := tx.ExecContext(
			ctx,
			"DELETE FROM playlist_song WHERE playlist_id = ?",
			playlist.ID,
		); err != nil {
			tx.Rollback()
			c.Logger().Errorf(
				"error Delete playlist_song by id=%d: %s",
				playlist.ID, err,
			)
			return errorResponse(c, 500, "internal server error")
		}
	}

	if 0 < len(songULIDs) {
		// songULIDs で select
		ss, err := getSongsByULIDs(ctx, tx, songULIDs)
		if err != nil {
			tx.Rollback()
			c.Logger().Errorf("getSongsByULIDs: %s", err)
			return errorResponse(c, 500, "internal server error")
		}
		// 数が合わなければ 400
		if len(ss) != len(songULIDs) {
			tx.Rollback()
			return errorResponse(c, 400, fmt.Sprintf("song not found. %v ---- %v", len(ss), len(songULIDs)))
		}

		// bulk insert
		query := `INSERT INTO playlist_song (playlist_id, sort_order, song_id) VALUES (:playlist_id, :sort_order, :song_id)`
		pss := make([]PlaylistSongRow, 0, len(ss))
		for idx, item := range ss {
			pss = append(pss, PlaylistSongRow{
				PlaylistID: playlist.ID,
				SortOrder:  idx + 1,
				SongID:     item.ID,
			})
		}

		if _, err := tx.NamedExec(query, pss); err != nil {
			tx.Rollback()
			c.Logger().Errorf("db.NamedExec: %s", err)
			return errorResponse(c, 500, "internal server error")
		}
	}

	if err := tx.Commit(); err != nil {
		c.Logger().Errorf("error tx.Commit: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	playlistDetails, err := getPlaylistDetailByPlaylistULID(ctx, conn, playlist.ULID, &userAccount)
	if err != nil {
		c.Logger().Errorf("error getPlaylistDetailByPlaylistULID: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlistDetails == nil {
		return errorResponse(c, 500, "error occured: getPlaylistDetailByPlaylistULID")
	}

	body := SinglePlaylistResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		Playlist: *playlistDetails,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// POST /api/playlist/delete

func apiPlaylistDeleteHandler(c echo.Context) error {
	_, valid, err := validateSession(c)
	if err != nil {
		c.Logger().Errorf("error validateSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if !valid {
		return errorResponse(c, 401, "login required")
	}
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	_account := sess.Values["user_account"]
	userAccount := _account.(string)

	playlistULID := c.Param("playlistUlid")
	// validation
	if playlistULID == "" {
		return errorResponse(c, 404, "bad playlist ulid")
	}
	if matched, _ := regexp.MatchString("[^a-zA-Z0-9]", playlistULID); matched {
		return errorResponse(c, 404, "bad playlist ulid")
	}

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	playlist, err := getPlaylistByULID(ctx, conn, playlistULID)
	if err != nil {
		c.Logger().Errorf("error getPlaylistByULID: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlist == nil {
		return errorResponse(c, 400, "playlist not found")
	}

	if playlist.UserAccount != userAccount {
		return errorResponse(c, 400, "do not delete other users playlist")
	}

	if _, err := conn.ExecContext(
		ctx,
		"DELETE FROM playlist WHERE `ulid` = ?",
		playlist.ULID,
	); err != nil {
		c.Logger().Errorf("error Delete playlist by ulid=%s: %s", playlist.ULID, err)
		return errorResponse(c, 500, "internal server error")
	}
	if _, err := conn.ExecContext(
		ctx,
		"DELETE FROM playlist_song WHERE playlist_id = ?",
		playlist.ID,
	); err != nil {
		c.Logger().Errorf("error Delete playlist_song by id=%s: %s", playlist.ID, err)
		return errorResponse(c, 500, "internal server error")
	}
	if _, err := conn.ExecContext(
		ctx,
		"DELETE FROM playlist_favorite WHERE playlist_id = ?",
		playlist.ID,
	); err != nil {
		c.Logger().Errorf("error Delete playlist_favorite by id=%s: %s", playlist.ID, err)
		return errorResponse(c, 500, "internal server error")
	}

	// if _, err := redisClient.ZRem(ctx, popularPlaylistCacheKey, playlist.ID).Result(); err != nil {
	// 	c.Logger().Errorf("error redisClient.Del : %s", err)
	// 	return errorResponse(c, 500, "internal server error")
	// }

	body := BasicResponse{
		Result: true,
		Status: 200,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// POST /api/playlist/:playlistUlid/favorite

func apiPlaylistFavoriteHandler(c echo.Context) error {
	user, ok, err := validateSession(c)
	if err != nil {
		c.Logger().Errorf("error validateSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if !ok || user == nil {
		return errorResponse(c, 401, "login required")
	}
	sess, err := getSession(c.Request())
	if err != nil {
		c.Logger().Errorf("error getSession:  %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	_account := sess.Values["user_account"]
	userAccount := _account.(string)

	playlistULID := c.Param("playlistUlid")
	var favoritePlaylistRequest FavoritePlaylistRequest
	if err := c.Bind(&favoritePlaylistRequest); err != nil {
		c.Logger().Errorf("error Bind to FavoritePlaylistRequest: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	isFavorited := favoritePlaylistRequest.IsFavorited
	if playlistULID == "" {
		return errorResponse(c, 404, "bad playlist ulid")
	}
	if matched, _ := regexp.MatchString("[^a-zA-Z0-9]", playlistULID); matched {
		return errorResponse(c, 404, "bad playlist ulid")
	}

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	playlist, err := getPlaylistByULID(ctx, conn, playlistULID)
	if err != nil {
		c.Logger().Errorf("error getPlaylistByULID: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlist == nil {
		return errorResponse(c, 404, "playlist not found")
	}
	// 操作対象のプレイリストが他のユーザーの場合、banされているかプレイリストがprivateならばnot found
	if playlist.UserAccount != user.Account {
		if user.IsBan || !playlist.IsPublic {
			return errorResponse(c, 404, "playlist not found")
		}
	}

	if isFavorited {
		// insert
		createdTimestamp := time.Now()
		playlistFavorite, err := getPlaylistFavoritesByPlaylistIDAndUserAccount(
			ctx, conn, playlist.ID, userAccount,
		)
		if err != nil {
			c.Logger().Errorf("error getPlaylistFavoritesByPlaylistIDAndUserAccount: %s", err)
			return errorResponse(c, 500, "internal server error")
		}
		if playlistFavorite == nil {
			if err := insertPlaylistFavorite(ctx, conn, playlist.ID, userAccount, createdTimestamp); err != nil {
				c.Logger().Errorf("error insertPlaylistFavorite: %s", err)
				return errorResponse(c, 500, "internal server error")
			}
		}
		re, err := redisClient.ZIncrBy(ctx, favPlaylistCacheKey, 1, fmt.Sprintf("%v", playlist.ID)).Result()
		if err != nil {
			c.Logger().Errorf("error redisClient.ZIncrBy : %s", err)
			return errorResponse(c, 500, "internal server error")
		}
		redisClient.ZAdd(ctx, popularPlaylistCacheKey, redis.Z{
			Score:  re,
			Member: playlist.ID,
		})
	} else {
		// delete
		if _, err := conn.ExecContext(
			ctx,
			"DELETE FROM playlist_favorite WHERE `playlist_id` = ? AND `favorite_user_account` = ?",
			playlist.ID, userAccount,
		); err != nil {
			c.Logger().Errorf(
				"error Delete playlist_favorite by playlist_id=%d, favorite_user_account=%s: %s",
				playlist.ID, userAccount, err,
			)
			return errorResponse(c, 500, "internal server error")
		}
		re, err := redisClient.ZIncrBy(ctx, favPlaylistCacheKey, -1, fmt.Sprintf("%v", playlist.ID)).Result()
		if err != nil {
			c.Logger().Errorf("error redisClient.ZIncrBy : %s", err)
			return errorResponse(c, 500, "internal server error")
		}
		if re < 0 {
			_, err := redisClient.ZIncrBy(ctx, favPlaylistCacheKey, 1, fmt.Sprintf("%v", playlist.ID)).Result()
			if err != nil {
				c.Logger().Errorf("error redisClient.ZIncrBy : %s", err)
				return errorResponse(c, 500, "internal server error")
			}
			redisClient.ZAdd(ctx, popularPlaylistCacheKey, redis.Z{
				Score:  0,
				Member: playlist.ID,
			})
		} else {
			redisClient.ZAdd(ctx, popularPlaylistCacheKey, redis.Z{
				Score:  re,
				Member: playlist.ID,
			})
		}
	}

	playlistDetail, err := getPlaylistDetailByPlaylistULID(ctx, conn, playlist.ULID, &userAccount)
	if err != nil {
		c.Logger().Errorf("error getPlaylistDetailByPlaylistULID: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if playlistDetail == nil {
		return errorResponse(c, 404, "failed to fetch playlist detail")
	}

	body := SinglePlaylistResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		Playlist: *playlistDetail,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

// POST /api/admin/user/ban

func apiAdminUserBanHandler(c echo.Context) error {
	user, ok, err := validateSession(c)
	if err != nil {
		c.Logger().Errorf("error validateSession: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if !ok || user == nil {
		return errorResponse(c, 401, "login required")
	}
	// 管理者userであることを確認,でなければ403
	if !isAdminUser(user.Account) {
		return errorResponse(c, 403, "not admin user")
	}

	var adminPlayerBanRequest AdminPlayerBanRequest
	if err := c.Bind(&adminPlayerBanRequest); err != nil {
		c.Logger().Errorf("error Bind request to AdminPlayerBanRequest: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	userAccount := adminPlayerBanRequest.UserAccount
	isBan := adminPlayerBanRequest.IsBan

	ctx := c.Request().Context()
	conn, err := db.Connx(ctx)
	if err != nil {
		c.Logger().Errorf("error db.Conn: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	if _, err := conn.ExecContext(
		ctx,
		"UPDATE user SET `is_ban` = ?  WHERE `account` = ?",
		isBan, userAccount,
	); err != nil {
		c.Logger().Errorf("error Update user by is_ban=%t, account=%s: %s", isBan, userAccount, err)
		return errorResponse(c, 500, "internal server error")
	}
	updatedUser, err := getUserByAccount(ctx, conn, userAccount)
	if err != nil {
		c.Logger().Errorf("error getUserByAccount: %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	if updatedUser == nil {
		return errorResponse(c, 400, "user not found")
	}

	if isBan {
		banList.Store(updatedUser.Account, struct{}{})
	} else {
		banList.Delete(updatedUser.Account)
	}

	body := AdminPlayerBanResponse{
		BasicResponse: BasicResponse{
			Result: true,
			Status: 200,
		},
		UserAccount: updatedUser.Account,
		DisplayName: updatedUser.DisplayName,
		IsBan:       updatedUser.IsBan,
		CreatedAt:   updatedUser.CreatedAt,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}

func isAdminUser(account string) bool {
	return account == "adminuser"
}

// 競技に必要なAPI
// DBの初期化処理
// auto generated dump data 20220424_0851 size prod
func initializeHandler(c echo.Context) error {
	// lastCreatedAt := "2022-05-13 09:00:00.000"
	ctx := c.Request().Context()

	conn, err := db.Connx(ctx)
	if err != nil {
		return errorResponse(c, 500, "internal server error")
	}
	defer conn.Close()

	var popular []struct {
		PlaylistID    int `db:"playlist_id"`
		FavoriteCount int `db:"favorite_count"`
	}
	if err := db.SelectContext(
		ctx,
		&popular,
		`SELECT playlist_id, count(*) AS favorite_count FROM playlist_favorite GROUP BY playlist_id ORDER BY count(*) DESC`,
	); err != nil {
		c.Logger().Errorf("error: initialize %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	pargs := redis.ZAddArgs{
		Members: make([]redis.Z, 0, len(popular)),
	}
	for _, item := range popular {
		pargs.Members = append(pargs.Members, redis.Z{
			Score:  float64(item.FavoriteCount),
			Member: item.PlaylistID,
		})
	}

	_, err = redisClient.ZAddArgs(ctx, favPlaylistCacheKey, pargs).Result()
	if err != nil {
		c.Logger().Errorf("error: initialize %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	_, err = redisClient.ZAddArgs(ctx, popularPlaylistCacheKey, pargs).Result()
	if err != nil {
		c.Logger().Errorf("error: initialize %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	artistMap = map[int]string{}
	var ars []ArtistRow
	if err := db.SelectContext(
		ctx,
		&ars,
		"SELECT * FROM artist",
	); err != nil {
		c.Logger().Errorf("error: initialize %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	for _, item := range ars {
		artistMap[item.ID] = item.Name
	}

	banList = sync.Map{}
	userMap = sync.Map{}
	var uars []UserRow
	if err := db.SelectContext(
		ctx,
		&uars,
		"SELECT * FROM user",
	); err != nil {
		c.Logger().Errorf("error: initialize %s", err)
		return errorResponse(c, 500, "internal server error")
	}
	for _, item := range uars {
		i := item
		if item.IsBan {
			banList.Store(item.Account, struct{}{})
		}
		userMap.Store(i.Account, &i)
	}

	body := BasicResponse{
		Result: true,
		Status: 200,
	}
	if err := c.JSON(http.StatusOK, body); err != nil {
		c.Logger().Errorf("error returns JSON: %s", err)
		return errorResponse(c, 500, "internal server error")
	}

	return nil
}
