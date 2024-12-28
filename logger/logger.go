package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

var (
	// Log 全局日志实例
	Log *logrus.Logger
)

// Config 日志配置
type Config struct {
	// 日志级别: debug, info, warn, error
	Level string
	// 是否输出到文件
	ToFile bool
	// 日志文件路径
	FilePath string
	// 日志保留时间（天）
	MaxAge int
	// 日志轮转时间（小时）
	RotationTime int
}

// InitLogger 初始化日志系统
func InitLogger(config Config) error {
	// 创建日志实例
	Log = logrus.New()

	// 设置日志格式
	Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// 设置日志级别
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return fmt.Errorf("解析日志级别失败: %v", err)
	}
	Log.SetLevel(level)

	if config.ToFile {
		// 确保日志目录存在
		logDir := filepath.Dir(config.FilePath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("创建日志目录失败: %v", err)
		}

		// 创建日志轮转器
		rotator, err := rotatelogs.New(
			config.FilePath+".%Y%m%d%H",
			rotatelogs.WithLinkName(config.FilePath),
			rotatelogs.WithMaxAge(time.Duration(config.MaxAge)*24*time.Hour),
			rotatelogs.WithRotationTime(time.Duration(config.RotationTime)*time.Hour),
		)
		if err != nil {
			return fmt.Errorf("创建日志轮转器失败: %v", err)
		}

		// 同时输出到文件和控制台
		Log.SetOutput(io.MultiWriter(os.Stdout, rotator))
	}

	return nil
}

// Debug 输出调试日志
func Debug(format string, args ...interface{}) {
	if Log != nil {
		Log.Debugf(format, args...)
	}
}

// Info 输出信息日志
func Info(format string, args ...interface{}) {
	if Log != nil {
		Log.Infof(format, args...)
	}
}

// Warn 输出警告日志
func Warn(format string, args ...interface{}) {
	if Log != nil {
		Log.Warnf(format, args...)
	}
}

// Error 输出错误日志
func Error(format string, args ...interface{}) {
	if Log != nil {
		Log.Errorf(format, args...)
	}
}

// WithFields 创建带字段的日志条目
func WithFields(fields logrus.Fields) *logrus.Entry {
	if Log != nil {
		return Log.WithFields(fields)
	}
	return nil
}
