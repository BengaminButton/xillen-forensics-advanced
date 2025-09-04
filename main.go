package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var author = "t.me/Bengamin_Button t.me/XillenAdapter"

type FileInfo struct {
	Path        string
	Size        int64
	ModTime     time.Time
	HashMD5     string
	HashSHA1    string
	HashSHA256  string
	IsDeleted   bool
	FileType    string
	Permissions string
	Owner       string
	Group       string
}

type ForensicReport struct {
	ScanTime        time.Time
	TargetPath      string
	TotalFiles      int
	TotalSize       int64
	DeletedFiles    []FileInfo
	SuspiciousFiles []FileInfo
	HashDatabase    map[string][]FileInfo
	FileTypes       map[string]int
	Timeline        []FileInfo
}

type ForensicAnalyzer struct {
	report             *ForensicReport
	hashDB             map[string][]FileInfo
	suspiciousPatterns []string
	deletedPatterns    []string
}

func NewForensicAnalyzer() *ForensicAnalyzer {
	return &ForensicAnalyzer{
		report: &ForensicReport{
			ScanTime:     time.Now(),
			HashDatabase: make(map[string][]FileInfo),
			FileTypes:    make(map[string]int),
		},
		hashDB: make(map[string][]FileInfo),
		suspiciousPatterns: []string{
			"password", "secret", "key", "token", "credential",
			"admin", "root", "backdoor", "malware", "virus",
			"trojan", "exploit", "hack", "crack", "bypass",
		},
		deletedPatterns: []string{
			"$Recycle.Bin", "RECYCLER", "Trash", ".Trash",
			"$RECYCLE.BIN", "System Volume Information",
		},
	}
}

func (fa *ForensicAnalyzer) ScanDirectory(rootPath string) error {
	fmt.Printf("Начало сканирования: %s\n", rootPath)
	fa.report.TargetPath = rootPath

	return filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		fileInfo := fa.analyzeFile(path, info)
		fa.report.TotalFiles++
		fa.report.TotalSize += fileInfo.Size

		fa.updateFileTypes(fileInfo)
		fa.checkSuspiciousFile(fileInfo)
		fa.checkDeletedFile(fileInfo)
		fa.addToTimeline(fileInfo)
		fa.updateHashDatabase(fileInfo)

		if fa.report.TotalFiles%1000 == 0 {
			fmt.Printf("Обработано файлов: %d\n", fa.report.TotalFiles)
		}

		return nil
	})
}

func (fa *ForensicAnalyzer) analyzeFile(path string, info os.FileInfo) FileInfo {
	fileInfo := FileInfo{
		Path:        path,
		Size:        info.Size(),
		ModTime:     info.ModTime(),
		FileType:    fa.detectFileType(path),
		Permissions: info.Mode().String(),
	}

	if info.Mode().IsRegular() {
		fileInfo.HashMD5 = fa.calculateHash(path, "md5")
		fileInfo.HashSHA1 = fa.calculateHash(path, "sha1")
		fileInfo.HashSHA256 = fa.calculateHash(path, "sha256")
	}

	return fileInfo
}

func (fa *ForensicAnalyzer) calculateHash(filePath, algorithm string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var hash string
	switch algorithm {
	case "md5":
		hasher := md5.New()
		io.Copy(hasher, file)
		hash = hex.EncodeToString(hasher.Sum(nil))
	case "sha1":
		hasher := sha1.New()
		io.Copy(hasher, file)
		hash = hex.EncodeToString(hasher.Sum(nil))
	case "sha256":
		hasher := sha256.New()
		io.Copy(hasher, file)
		hash = hex.EncodeToString(hasher.Sum(nil))
	}

	return hash
}

func (fa *ForensicAnalyzer) detectFileType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))

	fileTypeMap := map[string]string{
		".exe":  "Executable",
		".dll":  "Dynamic Library",
		".sys":  "System File",
		".bat":  "Batch Script",
		".cmd":  "Command Script",
		".ps1":  "PowerShell Script",
		".vbs":  "VBScript",
		".js":   "JavaScript",
		".py":   "Python Script",
		".php":  "PHP Script",
		".html": "HTML Document",
		".htm":  "HTML Document",
		".css":  "CSS Stylesheet",
		".js":   "JavaScript",
		".json": "JSON Data",
		".xml":  "XML Document",
		".txt":  "Text Document",
		".log":  "Log File",
		".cfg":  "Configuration",
		".ini":  "Configuration",
		".reg":  "Registry File",
		".zip":  "Archive",
		".rar":  "Archive",
		".7z":   "Archive",
		".tar":  "Archive",
		".gz":   "Compressed Archive",
		".pdf":  "PDF Document",
		".doc":  "Word Document",
		".docx": "Word Document",
		".xls":  "Excel Spreadsheet",
		".xlsx": "Excel Spreadsheet",
		".ppt":  "PowerPoint Presentation",
		".pptx": "PowerPoint Presentation",
		".jpg":  "JPEG Image",
		".jpeg": "JPEG Image",
		".png":  "PNG Image",
		".gif":  "GIF Image",
		".bmp":  "Bitmap Image",
		".ico":  "Icon File",
		".mp3":  "MP3 Audio",
		".wav":  "WAV Audio",
		".mp4":  "MP4 Video",
		".avi":  "AVI Video",
		".mov":  "QuickTime Video",
		".wmv":  "Windows Media Video",
	}

	if fileType, exists := fileTypeMap[ext]; exists {
		return fileType
	}

	return "Unknown"
}

func (fa *ForensicAnalyzer) updateFileTypes(fileInfo FileInfo) {
	fa.report.FileTypes[fileInfo.FileType]++
}

func (fa *ForensicAnalyzer) checkSuspiciousFile(fileInfo FileInfo) {
	path := strings.ToLower(fileInfo.Path)

	for _, pattern := range fa.suspiciousPatterns {
		if strings.Contains(path, pattern) {
			fa.report.SuspiciousFiles = append(fa.report.SuspiciousFiles, fileInfo)
			return
		}
	}

	if fileInfo.FileType == "Executable" && fileInfo.Size < 1024*1024 {
		fa.report.SuspiciousFiles = append(fa.report.SuspiciousFiles, fileInfo)
	}
}

func (fa *ForensicAnalyzer) checkDeletedFile(fileInfo FileInfo) {
	path := strings.ToLower(fileInfo.Path)

	for _, pattern := range fa.deletedPatterns {
		if strings.Contains(path, pattern) {
			fileInfo.IsDeleted = true
			fa.report.DeletedFiles = append(fa.report.DeletedFiles, fileInfo)
			return
		}
	}
}

func (fa *ForensicAnalyzer) addToTimeline(fileInfo FileInfo) {
	fa.report.Timeline = append(fa.report.Timeline, fileInfo)
}

func (fa *ForensicAnalyzer) updateHashDatabase(fileInfo FileInfo) {
	if fileInfo.HashMD5 != "" {
		fa.report.HashDatabase[fileInfo.HashMD5] = append(fa.report.HashDatabase[fileInfo.HashMD5], fileInfo)
	}
}

func (fa *ForensicAnalyzer) FindDuplicates() map[string][]FileInfo {
	duplicates := make(map[string][]FileInfo)

	for hash, files := range fa.report.HashDatabase {
		if len(files) > 1 {
			duplicates[hash] = files
		}
	}

	return duplicates
}

func (fa *ForensicAnalyzer) SearchByPattern(pattern string) []FileInfo {
	var results []FileInfo
	regex, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return results
	}

	for _, file := range fa.report.Timeline {
		if regex.MatchString(file.Path) {
			results = append(results, file)
		}
	}

	return results
}

func (fa *ForensicAnalyzer) SearchByHash(hash string) []FileInfo {
	return fa.report.HashDatabase[hash]
}

func (fa *ForensicAnalyzer) SearchByDateRange(start, end time.Time) []FileInfo {
	var results []FileInfo

	for _, file := range fa.report.Timeline {
		if file.ModTime.After(start) && file.ModTime.Before(end) {
			results = append(results, file)
		}
	}

	return results
}

func (fa *ForensicAnalyzer) GenerateReport() string {
	var report strings.Builder

	report.WriteString("=== ОТЧЁТ ФОРЕНЗИК-АНАЛИЗА ===\n")
	report.WriteString(fmt.Sprintf("Время сканирования: %s\n", fa.report.ScanTime.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Целевой путь: %s\n", fa.report.TargetPath))
	report.WriteString(fmt.Sprintf("Всего файлов: %d\n", fa.report.TotalFiles))
	report.WriteString(fmt.Sprintf("Общий размер: %s\n", formatBytes(fa.report.TotalSize)))
	report.WriteString(fmt.Sprintf("Подозрительных файлов: %d\n", len(fa.report.SuspiciousFiles)))
	report.WriteString(fmt.Sprintf("Удалённых файлов: %d\n", len(fa.report.DeletedFiles)))

	report.WriteString("\n=== ТИПЫ ФАЙЛОВ ===\n")
	for fileType, count := range fa.report.FileTypes {
		report.WriteString(fmt.Sprintf("%s: %d\n", fileType, count))
	}

	report.WriteString("\n=== ПОДОЗРИТЕЛЬНЫЕ ФАЙЛЫ ===\n")
	for _, file := range fa.report.SuspiciousFiles {
		report.WriteString(fmt.Sprintf("%s (%s, %s)\n", file.Path, file.FileType, formatBytes(file.Size)))
	}

	report.WriteString("\n=== УДАЛЁННЫЕ ФАЙЛЫ ===\n")
	for _, file := range fa.report.DeletedFiles {
		report.WriteString(fmt.Sprintf("%s (%s, %s)\n", file.Path, file.FileType, formatBytes(file.Size)))
	}

	duplicates := fa.FindDuplicates()
	report.WriteString(fmt.Sprintf("\n=== ДУБЛИКАТЫ (%d групп) ===\n", len(duplicates)))
	for hash, files := range duplicates {
		report.WriteString(fmt.Sprintf("Hash: %s\n", hash))
		for _, file := range files {
			report.WriteString(fmt.Sprintf("  %s\n", file.Path))
		}
	}

	return report.String()
}

func (fa *ForensicAnalyzer) SaveReport(filename string) error {
	report := fa.GenerateReport()
	return os.WriteFile(filename, []byte(report), 0644)
}

func (fa *ForensicAnalyzer) ExportTimeline(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.WriteString("Timestamp,Path,Size,Type,Hash\n")

	sort.Slice(fa.report.Timeline, func(i, j int) bool {
		return fa.report.Timeline[i].ModTime.Before(fa.report.Timeline[j].ModTime)
	})

	for _, file := range fa.report.Timeline {
		writer.WriteString(fmt.Sprintf("%s,%s,%d,%s,%s\n",
			file.ModTime.Format("2006-01-02 15:04:05"),
			file.Path,
			file.Size,
			file.FileType,
			file.HashMD5))
	}

	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func main() {
	fmt.Println(author)
	fmt.Println("=== XILLEN FORENSICS ADVANCED ===")

	if len(os.Args) < 2 {
		fmt.Println("Использование: ./main <директория> [опции]")
		fmt.Println("Опции:")
		fmt.Println("  -report <файл>     Сохранить отчёт в файл")
		fmt.Println("  -timeline <файл>   Экспортировать временную линию в CSV")
		fmt.Println("  -search <паттерн>  Поиск файлов по паттерну")
		fmt.Println("  -hash <хеш>        Поиск файлов по хешу")
		fmt.Println("  -duplicates        Показать только дубликаты")
		return
	}

	targetPath := os.Args[1]
	analyzer := NewForensicAnalyzer()

	err := analyzer.ScanDirectory(targetPath)
	if err != nil {
		fmt.Printf("Ошибка сканирования: %v\n", err)
		return
	}

	fmt.Println("\nСканирование завершено!")
	fmt.Println(analyzer.GenerateReport())

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-report":
			if i+1 < len(os.Args) {
				filename := os.Args[i+1]
				err := analyzer.SaveReport(filename)
				if err != nil {
					fmt.Printf("Ошибка сохранения отчёта: %v\n", err)
				} else {
					fmt.Printf("Отчёт сохранён в %s\n", filename)
				}
				i++
			}
		case "-timeline":
			if i+1 < len(os.Args) {
				filename := os.Args[i+1]
				err := analyzer.ExportTimeline(filename)
				if err != nil {
					fmt.Printf("Ошибка экспорта временной линии: %v\n", err)
				} else {
					fmt.Printf("Временная линия экспортирована в %s\n", filename)
				}
				i++
			}
		case "-search":
			if i+1 < len(os.Args) {
				pattern := os.Args[i+1]
				results := analyzer.SearchByPattern(pattern)
				fmt.Printf("\nРезультаты поиска по паттерну '%s': %d файлов\n", pattern, len(results))
				for _, file := range results {
					fmt.Printf("  %s\n", file.Path)
				}
				i++
			}
		case "-hash":
			if i+1 < len(os.Args) {
				hash := os.Args[i+1]
				results := analyzer.SearchByHash(hash)
				fmt.Printf("\nРезультаты поиска по хешу '%s': %d файлов\n", hash, len(results))
				for _, file := range results {
					fmt.Printf("  %s\n", file.Path)
				}
				i++
			}
		case "-duplicates":
			duplicates := analyzer.FindDuplicates()
			fmt.Printf("\n=== ДУБЛИКАТЫ (%d групп) ===\n", len(duplicates))
			for hash, files := range duplicates {
				fmt.Printf("Hash: %s\n", hash)
				for _, file := range files {
					fmt.Printf("  %s (%s)\n", file.Path, formatBytes(file.Size))
				}
			}
		}
	}
}
