import os
import sys
import hashlib
import json
import time
import struct
import binascii
from datetime import datetime, timedelta
import sqlite3
import argparse
from pathlib import Path
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

author = "t.me/Bengamin_Button t.me/XillenAdapter"

class XillenForensicsAdvanced:
    def __init__(self):
        self.evidence = []
        self.artifacts = []
        self.config = {
            'output_directory': './forensics_output',
            'max_file_size': 100 * 1024 * 1024,
            'threads': 4,
            'hash_algorithms': ['md5', 'sha1', 'sha256'],
            'file_types': {
                'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
                'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf'],
                'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
                'executables': ['.exe', '.dll', '.sys', '.com', '.scr'],
                'logs': ['.log', '.txt', '.csv'],
                'databases': ['.db', '.sqlite', '.sqlite3', '.mdb']
            },
            'suspicious_extensions': ['.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js'],
            'deleted_file_recovery': True,
            'metadata_extraction': True,
            'timeline_analysis': True
        }
        self.statistics = {
            'files_analyzed': 0,
            'artifacts_found': 0,
            'evidence_collected': 0,
            'start_time': time.time()
        }
        self.setup_output_directory()
        self.setup_database()
    
    def setup_output_directory(self):
        if not os.path.exists(self.config['output_directory']):
            os.makedirs(self.config['output_directory'])
        
        subdirs = ['evidence', 'artifacts', 'reports', 'timeline', 'hashes']
        for subdir in subdirs:
            path = os.path.join(self.config['output_directory'], subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def setup_database(self):
        self.db_path = os.path.join(self.config['output_directory'], 'forensics.db')
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                file_hash_md5 TEXT,
                file_hash_sha1 TEXT,
                file_hash_sha256 TEXT,
                file_type TEXT,
                created_time DATETIME,
                modified_time DATETIME,
                accessed_time DATETIME,
                permissions TEXT,
                is_deleted BOOLEAN,
                metadata TEXT,
                suspicious_score INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                description TEXT,
                file_path TEXT,
                content TEXT,
                timestamp DATETIME,
                relevance_score INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                event_type TEXT,
                description TEXT,
                file_path TEXT,
                user TEXT,
                system TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def calculate_file_hashes(self, file_path):
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                if 'md5' in self.config['hash_algorithms']:
                    hashes['md5'] = hashlib.md5(data).hexdigest()
                
                if 'sha1' in self.config['hash_algorithms']:
                    hashes['sha1'] = hashlib.sha1(data).hexdigest()
                
                if 'sha256' in self.config['hash_algorithms']:
                    hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
        except Exception as e:
            print(f"Ошибка вычисления хешей для {file_path}: {e}")
        
        return hashes
    
    def get_file_metadata(self, file_path):
        try:
            stat = os.stat(file_path)
            metadata = {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:],
                'inode': stat.st_ino,
                'device': stat.st_dev
            }
            return metadata
        except Exception as e:
            print(f"Ошибка получения метаданных для {file_path}: {e}")
            return None
    
    def analyze_file_type(self, file_path):
        file_ext = os.path.splitext(file_path)[1].lower()
        
        for category, extensions in self.config['file_types'].items():
            if file_ext in extensions:
                return category
        
        if file_ext in self.config['suspicious_extensions']:
            return 'suspicious'
        
        return 'unknown'
    
    def calculate_suspicious_score(self, file_path, metadata, file_type):
        score = 0
        
        file_ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path).lower()
        
        if file_ext in self.config['suspicious_extensions']:
            score += 30
        
        if file_type == 'executables':
            score += 25
        
        if 'temp' in file_path.lower() or 'tmp' in file_path.lower():
            score += 10
        
        if file_name.startswith('.') and file_name != '.' and file_name != '..':
            score += 15
        
        if metadata and metadata['size'] == 0:
            score += 5
        
        if file_ext in ['.exe', '.dll', '.sys'] and metadata and metadata['size'] < 1024:
            score += 20
        
        if 'system32' in file_path.lower() and file_ext in ['.exe', '.dll']:
            score += 10
        
        return min(score, 100)
    
    def extract_file_metadata(self, file_path):
        if not self.config['metadata_extraction']:
            return {}
        
        metadata = {}
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext in ['.jpg', '.jpeg', '.png', '.tiff']:
                metadata.update(self.extract_image_metadata(file_path))
            elif file_ext in ['.pdf']:
                metadata.update(self.extract_pdf_metadata(file_path))
            elif file_ext in ['.doc', '.docx']:
                metadata.update(self.extract_document_metadata(file_path))
            elif file_ext in ['.exe', '.dll']:
                metadata.update(self.extract_executable_metadata(file_path))
        except Exception as e:
            print(f"Ошибка извлечения метаданных для {file_path}: {e}")
        
        return metadata
    
    def extract_image_metadata(self, file_path):
        metadata = {}
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
                if header.startswith(b'\xff\xd8\xff'):
                    metadata['format'] = 'JPEG'
                elif header.startswith(b'\x89PNG'):
                    metadata['format'] = 'PNG'
                elif header.startswith(b'GIF8'):
                    metadata['format'] = 'GIF'
                elif header.startswith(b'BM'):
                    metadata['format'] = 'BMP'
                elif header.startswith(b'II*\x00') or header.startswith(b'MM\x00*'):
                    metadata['format'] = 'TIFF'
        except:
            pass
        
        return metadata
    
    def extract_pdf_metadata(self, file_path):
        metadata = {}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)
                
                if b'%PDF' in content:
                    metadata['format'] = 'PDF'
                    
                    if b'/Title' in content:
                        start = content.find(b'/Title')
                        if start != -1:
                            end = content.find(b'>>', start)
                            if end != -1:
                                title = content[start:end].decode('utf-8', errors='ignore')
                                metadata['title'] = title
        except:
            pass
        
        return metadata
    
    def extract_document_metadata(self, file_path):
        metadata = {}
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                
                if header.startswith(b'PK\x03\x04'):
                    metadata['format'] = 'ZIP-based document'
                elif header.startswith(b'\xd0\xcf\x11\xe0'):
                    metadata['format'] = 'Microsoft Office document'
        except:
            pass
        
        return metadata
    
    def extract_executable_metadata(self, file_path):
        metadata = {}
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(64)
                
                if header.startswith(b'MZ'):
                    metadata['format'] = 'PE executable'
                    
                    pe_offset = struct.unpack('<I', header[60:64])[0]
                    f.seek(pe_offset)
                    pe_header = f.read(4)
                    
                    if pe_header == b'PE\x00\x00':
                        metadata['pe_format'] = True
                        
                        machine = struct.unpack('<H', f.read(2))[0]
                        if machine == 0x014c:
                            metadata['architecture'] = 'x86'
                        elif machine == 0x8664:
                            metadata['architecture'] = 'x64'
        except:
            pass
        
        return metadata
    
    def analyze_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                return None
            
            file_size = os.path.getsize(file_path)
            if file_size > self.config['max_file_size']:
                print(f"⚠️  Файл слишком большой: {file_path}")
                return None
            
            hashes = self.calculate_file_hashes(file_path)
            metadata = self.get_file_metadata(file_path)
            file_type = self.analyze_file_type(file_path)
            suspicious_score = self.calculate_suspicious_score(file_path, metadata, file_type)
            extracted_metadata = self.extract_file_metadata(file_path)
            
            evidence = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': file_size,
                'file_hash_md5': hashes.get('md5', ''),
                'file_hash_sha1': hashes.get('sha1', ''),
                'file_hash_sha256': hashes.get('sha256', ''),
                'file_type': file_type,
                'created_time': metadata['created'] if metadata else None,
                'modified_time': metadata['modified'] if metadata else None,
                'accessed_time': metadata['accessed'] if metadata else None,
                'permissions': metadata['permissions'] if metadata else None,
                'is_deleted': False,
                'metadata': json.dumps(extracted_metadata),
                'suspicious_score': suspicious_score,
                'timestamp': datetime.now().isoformat()
            }
            
            self.save_evidence(evidence)
            self.statistics['files_analyzed'] += 1
            
            if suspicious_score > 50:
                self.statistics['artifacts_found'] += 1
                self.create_artifact('suspicious_file', f'Подозрительный файл: {file_path}', file_path, suspicious_score)
            
            return evidence
            
        except Exception as e:
            print(f"❌ Ошибка анализа файла {file_path}: {e}")
            return None
    
    def save_evidence(self, evidence):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO evidence (file_path, file_name, file_size, file_hash_md5, file_hash_sha1, 
                                file_hash_sha256, file_type, created_time, modified_time, accessed_time,
                                permissions, is_deleted, metadata, suspicious_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence['file_path'], evidence['file_name'], evidence['file_size'],
            evidence['file_hash_md5'], evidence['file_hash_sha1'], evidence['file_hash_sha256'],
            evidence['file_type'], evidence['created_time'], evidence['modified_time'],
            evidence['accessed_time'], evidence['permissions'], evidence['is_deleted'],
            evidence['metadata'], evidence['suspicious_score'], evidence['timestamp']
        ))
        self.conn.commit()
    
    def create_artifact(self, artifact_type, description, file_path, relevance_score):
        artifact = {
            'type': artifact_type,
            'description': description,
            'file_path': file_path,
            'content': '',
            'timestamp': datetime.now().isoformat(),
            'relevance_score': relevance_score
        }
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO artifacts (type, description, file_path, content, timestamp, relevance_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            artifact['type'], artifact['description'], artifact['file_path'],
            artifact['content'], artifact['timestamp'], artifact['relevance_score']
        ))
        self.conn.commit()
        
        self.artifacts.append(artifact)
    
    def scan_directory(self, directory_path):
        print(f"🔍 Сканирование директории: {directory_path}")
        
        file_queue = queue.Queue()
        results_queue = queue.Queue()
        
        def worker():
            while True:
                try:
                    file_path = file_queue.get(timeout=1)
                    result = self.analyze_file(file_path)
                    if result:
                        results_queue.put(result)
                    file_queue.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"❌ Ошибка воркера: {e}")
                    file_queue.task_done()
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_queue.put(file_path)
        
        threads = []
        for i in range(self.config['threads']):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)
        
        file_queue.join()
        
        for thread in threads:
            thread.join()
        
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        print(f"✅ Сканирование завершено. Проанализировано {len(results)} файлов")
        return results
    
    def search_deleted_files(self, directory_path):
        if not self.config['deleted_file_recovery']:
            return []
        
        print("🔍 Поиск удаленных файлов...")
        deleted_files = []
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read(1024)
                            
                            if b'\x00' in content and len(content) > 100:
                                deleted_files.append({
                                    'path': file_path,
                                    'size': len(content),
                                    'type': 'potential_deleted_file'
                                })
                    except:
                        pass
        except Exception as e:
            print(f"❌ Ошибка поиска удаленных файлов: {e}")
        
        return deleted_files
    
    def analyze_timeline(self, directory_path):
        if not self.config['timeline_analysis']:
            return []
        
        print("📅 Анализ временной шкалы...")
        timeline_events = []
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        stat = os.stat(file_path)
                        
                        timeline_events.append({
                            'timestamp': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'event_type': 'file_created',
                            'description': f'Файл создан: {file}',
                            'file_path': file_path,
                            'user': 'system',
                            'system': 'filesystem'
                        })
                        
                        timeline_events.append({
                            'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'event_type': 'file_modified',
                            'description': f'Файл изменен: {file}',
                            'file_path': file_path,
                            'user': 'system',
                            'system': 'filesystem'
                        })
                        
                        timeline_events.append({
                            'timestamp': datetime.fromtimestamp(stat.st_atime).isoformat(),
                            'event_type': 'file_accessed',
                            'description': f'Файл открыт: {file}',
                            'file_path': file_path,
                            'user': 'system',
                            'system': 'filesystem'
                        })
                    except:
                        pass
        except Exception as e:
            print(f"❌ Ошибка анализа временной шкалы: {e}")
        
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        for event in timeline_events:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO timeline (timestamp, event_type, description, file_path, user, system)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                event['timestamp'], event['event_type'], event['description'],
                event['file_path'], event['user'], event['system']
            ))
            self.conn.commit()
        
        return timeline_events
    
    def generate_report(self):
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM evidence')
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM evidence WHERE suspicious_score > 50')
        suspicious_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM artifacts')
        total_artifacts = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM timeline')
        timeline_events = cursor.fetchone()[0]
        
        cursor.execute('SELECT * FROM evidence WHERE suspicious_score > 70 ORDER BY suspicious_score DESC LIMIT 10')
        top_suspicious = cursor.fetchall()
        
        cursor.execute('SELECT * FROM artifacts ORDER BY relevance_score DESC LIMIT 10')
        top_artifacts = cursor.fetchall()
        
        report = {
            'metadata': {
                'author': author,
                'timestamp': datetime.now().isoformat(),
                'version': '2.0.0',
                'statistics': self.statistics
            },
            'summary': {
                'total_files_analyzed': total_files,
                'suspicious_files_found': suspicious_files,
                'artifacts_found': total_artifacts,
                'timeline_events': timeline_events
            },
            'top_suspicious_files': [
                {
                    'file_path': row[1],
                    'file_name': row[2],
                    'suspicious_score': row[14],
                    'file_type': row[7]
                } for row in top_suspicious
            ],
            'top_artifacts': [
                {
                    'type': row[1],
                    'description': row[2],
                    'file_path': row[3],
                    'relevance_score': row[6]
                } for row in top_artifacts
            ]
        }
        
        return report
    
    def save_report(self, filename):
        report = self.generate_report()
        report_path = os.path.join(self.config['output_directory'], 'reports', filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📄 Отчет сохранен: {report_path}")
    
    def export_evidence(self, filename):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM evidence')
        evidence_data = cursor.fetchall()
        
        export_path = os.path.join(self.config['output_directory'], 'evidence', filename)
        
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write("File Path,File Name,File Size,MD5,SHA1,SHA256,File Type,Suspicious Score,Timestamp\n")
            for row in evidence_data:
                f.write(f"{row[1]},{row[2]},{row[3]},{row[4]},{row[5]},{row[6]},{row[7]},{row[14]},{row[15]}\n")
        
        print(f"📊 Данные экспортированы: {export_path}")
    
    def get_statistics(self):
        uptime = time.time() - self.statistics['start_time']
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM evidence')
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM evidence WHERE suspicious_score > 50')
        suspicious_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM artifacts')
        total_artifacts = cursor.fetchone()[0]
        
        return {
            **self.statistics,
            'uptime': f'{hours}ч {minutes}м',
            'total_files': total_files,
            'suspicious_files': suspicious_files,
            'total_artifacts': total_artifacts
        }
    
    def show_statistics(self):
        stats = self.get_statistics()
        
        print(f"\n📊 Статистика криминалистического анализа:")
        print(f"   Автор: {author}")
        print(f"   Время работы: {stats['uptime']}")
        print(f"   Файлов проанализировано: {stats['files_analyzed']}")
        print(f"   Подозрительных файлов: {stats['suspicious_files']}")
        print(f"   Артефактов найдено: {stats['total_artifacts']}")
        print(f"   Доказательств собрано: {stats['evidence_collected']}")
    
    def show_menu(self):
        print(f"\n🔍 Xillen Forensics Advanced")
        print(f"👨‍💻 Автор: {author}")
        print(f"\nОпции:")
        print(f"1. Анализ файла")
        print(f"2. Сканирование директории")
        print(f"3. Поиск удаленных файлов")
        print(f"4. Анализ временной шкалы")
        print(f"5. Показать подозрительные файлы")
        print(f"6. Показать артефакты")
        print(f"7. Генерировать отчет")
        print(f"8. Экспорт данных")
        print(f"9. Показать статистику")
        print(f"10. Настройки")
        print(f"0. Выход")
    
    def interactive_mode(self):
        while True:
            self.show_menu()
            choice = input("\nВыберите опцию: ").strip()
            
            try:
                if choice == '1':
                    file_path = input("Путь к файлу: ").strip()
                    if os.path.exists(file_path):
                        result = self.analyze_file(file_path)
                        if result:
                            print(f"✅ Файл проанализирован. Подозрительность: {result['suspicious_score']}/100")
                    else:
                        print("❌ Файл не найден")
                
                elif choice == '2':
                    directory = input("Путь к директории: ").strip()
                    if os.path.exists(directory):
                        self.scan_directory(directory)
                    else:
                        print("❌ Директория не найдена")
                
                elif choice == '3':
                    directory = input("Путь к директории: ").strip()
                    if os.path.exists(directory):
                        deleted_files = self.search_deleted_files(directory)
                        print(f"🔍 Найдено {len(deleted_files)} потенциально удаленных файлов")
                    else:
                        print("❌ Директория не найдена")
                
                elif choice == '4':
                    directory = input("Путь к директории: ").strip()
                    if os.path.exists(directory):
                        timeline = self.analyze_timeline(directory)
                        print(f"📅 Проанализировано {len(timeline)} событий временной шкалы")
                    else:
                        print("❌ Директория не найдена")
                
                elif choice == '5':
                    cursor = self.conn.cursor()
                    cursor.execute('SELECT file_path, file_name, suspicious_score FROM evidence WHERE suspicious_score > 50 ORDER BY suspicious_score DESC LIMIT 20')
                    suspicious = cursor.fetchall()
                    
                    if suspicious:
                        print(f"\n⚠️  Подозрительные файлы:")
                        for i, (path, name, score) in enumerate(suspicious, 1):
                            print(f"{i}. {name} - {score}/100")
                    else:
                        print("Подозрительных файлов не найдено")
                
                elif choice == '6':
                    cursor = self.conn.cursor()
                    cursor.execute('SELECT type, description, relevance_score FROM artifacts ORDER BY relevance_score DESC LIMIT 20')
                    artifacts = cursor.fetchall()
                    
                    if artifacts:
                        print(f"\n🔍 Найденные артефакты:")
                        for i, (type, description, score) in enumerate(artifacts, 1):
                            print(f"{i}. {type}: {description} - {score}/100")
                    else:
                        print("Артефакты не найдены")
                
                elif choice == '7':
                    filename = input("Имя файла отчета: ").strip()
                    if not filename:
                        filename = f"forensics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    self.save_report(filename)
                
                elif choice == '8':
                    filename = input("Имя файла экспорта: ").strip()
                    if not filename:
                        filename = f"evidence_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    self.export_evidence(filename)
                
                elif choice == '9':
                    self.show_statistics()
                
                elif choice == '10':
                    print(f"\n⚙️  Настройки:")
                    print(f"   Выходная директория: {self.config['output_directory']}")
                    print(f"   Максимальный размер файла: {self.config['max_file_size'] / 1024 / 1024} МБ")
                    print(f"   Количество потоков: {self.config['threads']}")
                    print(f"   Алгоритмы хеширования: {', '.join(self.config['hash_algorithms'])}")
                    print(f"   Восстановление удаленных файлов: {'Включено' if self.config['deleted_file_recovery'] else 'Отключено'}")
                    print(f"   Извлечение метаданных: {'Включено' if self.config['metadata_extraction'] else 'Отключено'}")
                    print(f"   Анализ временной шкалы: {'Включен' if self.config['timeline_analysis'] else 'Отключен'}")
                
                elif choice == '0':
                    print("👋 До свидания!")
                    break
                
                else:
                    print("❌ Неверный выбор")
            
            except Exception as e:
                print(f"❌ Ошибка: {e}")

def main():
    print(author)
    
    forensics = XillenForensicsAdvanced()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'analyze' and len(sys.argv) > 2:
            file_path = sys.argv[2]
            if os.path.exists(file_path):
                result = forensics.analyze_file(file_path)
                if result:
                    print(f"Результат анализа: {result['suspicious_score']}/100")
            else:
                print("Файл не найден")
        elif sys.argv[1] == 'scan' and len(sys.argv) > 2:
            directory = sys.argv[2]
            if os.path.exists(directory):
                forensics.scan_directory(directory)
                forensics.save_report('scan_report.json')
            else:
                print("Директория не найдена")
        else:
            print("Использование:")
            print("  python main.py analyze <файл>")
            print("  python main.py scan <директория>")
    else:
        forensics.interactive_mode()

if __name__ == "__main__":
    main()
