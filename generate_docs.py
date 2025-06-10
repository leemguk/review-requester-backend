import os
import fnmatch

def should_ignore_file(filepath, ignore_patterns):
    """Check if file should be ignored based on patterns"""
    filename = os.path.basename(filepath)
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(filepath, pattern):
            return True
    return False

def get_language_from_extension(filepath):
    """Get language identifier for markdown code blocks based on file extension"""
    ext_to_lang = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.jsx': 'javascript',
        '.html': 'html',
        '.css': 'css',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.sh': 'bash',
        '.sql': 'sql',
        '.json': 'json',
        '.xml': 'xml',
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.md': 'markdown',
        '.txt': 'text'
    }

    _, ext = os.path.splitext(filepath.lower())
    return ext_to_lang.get(ext, 'text')

def generate_code_documentation(root_dir='.', markdown_file='code_documentation.md', text_file='code_documentation.txt'):
    """Generate both markdown and plain text documentation of all code files in the project"""

    # Common files/patterns to ignore
    ignore_patterns = [
        '*.pyc', '__pycache__', '.git', '.gitignore', 
        'node_modules', '.env', '*.log', '.DS_Store',
        '*.min.js', '*.min.css', 'package-lock.json',
        'yarn.lock', '.replit', 'replit.nix', '*.md'
    ]

    # Common code file extensions
    code_extensions = {
        '.py', '.js', '.ts', '.tsx', '.jsx', '.html', '.css', '.java', 
        '.cpp', '.c', '.cs', '.php', '.rb', '.go', 
        '.rs', '.sh', '.sql', '.json', '.xml', '.yml', '.yaml'
    }

    markdown_content = []
    text_content = []

    # Headers for both formats
    markdown_content.append("# Project Code Documentation\n")
    markdown_content.append("This document contains all the code files in this project.\n")

    text_content.append("PROJECT CODE DOCUMENTATION\n")
    text_content.append("=" * 50 + "\n")
    text_content.append("This document contains all the code files in this project.\n\n")

    file_count = 0

    # Walk through all files in the project
    for root, dirs, files in os.walk(root_dir):
        print(f"Scanning directory: {root}")
        # Skip hidden directories and common ignore directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]

        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, root_dir)

            # Skip if file should be ignored
            if should_ignore_file(relative_path, ignore_patterns):
                continue

            # Only include files with code extensions
            _, ext = os.path.splitext(file.lower())
            if ext not in code_extensions:
                continue

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Add to markdown format
                markdown_content.append(f"\n## {relative_path}\n")
                language = get_language_from_extension(filepath)
                markdown_content.append(f"```{language}\n{content}\n```\n")

                # Add to plain text format
                text_content.append(f"\n{'='*60}\n")
                text_content.append(f"FILE: {relative_path}\n")
                text_content.append(f"{'='*60}\n\n")
                text_content.append(content)
                text_content.append("\n\n")

                file_count += 1
                print(f"Added: {relative_path}")

            except (UnicodeDecodeError, PermissionError) as e:
                print(f"Skipped {relative_path}: {e}")
                continue

    # Write both files
    try:
        # Write markdown file
        with open(markdown_file, 'w', encoding='utf-8') as f:
            f.write(''.join(markdown_content))
        print(f"\nMarkdown documentation generated: {markdown_file}")

        # Write plain text file
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(''.join(text_content))
        print(f"Plain text documentation generated: {text_file}")

        print(f"Total files processed: {file_count}")

    except Exception as e:
        print(f"Error writing output files: {e}")

if __name__ == "__main__":
    # You can customize these parameters
    ROOT_DIRECTORY = '.'  # Current directory (the Replit project root)
    MARKDOWN_FILE = 'code_documentation.md'
    TEXT_FILE = 'code_documentation.txt'

    generate_code_documentation(ROOT_DIRECTORY, MARKDOWN_FILE, TEXT_FILE)