package logger

import (
	"fmt"
	"github.com/chenyu116/yunjiasu-sync/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path/filepath"
)

// ZapLogger ZapLogger
var Zap *zap.Logger

// InitLogger InitLogger
func init() {
	cf := config.GetConfig()
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "trace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	//zapcore.EpochMillisTimeEncoder()
	//lv := zapcore.DebugLevel
	//err := lv.Set(logLevel)
	//if err != nil {
	//	lv = zapcore.InfoLevel
	//}
	lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.WarnLevel
	})
	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.WarnLevel
	})

	// High-priority output should also go to standard e, and low-priority
	// output should also go to standard out.
	consoleDebugging := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)

	// Optimize the Kafka output for machine consumption and the console output
	// for human operators.
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	// Join the outputs, encoders, and level-handling functions into
	// zapcore.Cores, then tee the four cores together.
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	//dir = "/media/roger/98B2D1FBB2D1DE36/workspace/api-equ"
	hook := lumberjack.Logger{
		Filename:   dir + "/logs/yunjiasu.txt", // ⽇志⽂件路径
		MaxSize:    cf.Log.MaxSize,            // megabytes
		MaxBackups: cf.Log.MaxBackups,         // 最多保留3个备份
		MaxAge:     cf.Log.MaxAge,             //days
		Compress:   cf.Log.Compress,           // 是否压缩 disabled by default
		LocalTime:  cf.Log.LocalTime,
	}
	fmt.Printf("zap log dir: %s/logs\n", dir)
	//syncer := cronowriter.MustNew("/media/roger/98B2D1FBB2D1DE36/workspace/api-equ/logs/%Y%m%d.log", cronowriter.WithLocation(time.Local))
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, highPriority),
		zapcore.NewCore(consoleEncoder, consoleDebugging, lowPriority),
		zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(&hook),
			highPriority),
	)

	Zap = zap.New(core, zap.AddCaller())
}
