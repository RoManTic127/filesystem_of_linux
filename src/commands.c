#include "../include/commands.h"
#include "../include/inode.h"
#include "../include/directory.h"
#include "../include/user.h"
#include "../include/disk.h"
#include "../include/ext2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// 文件操作命令
int cmd_create(const char *path) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    uint32_t parent_inode;
    char child_name[MAX_FILENAME];
    
    if (get_parent_inode(path, &parent_inode, child_name) != 0) {
        printf("Error: Invalid path\n");
        return -1;
    }
    
    if (parent_inode == 0) {
        printf("Error: Parent directory does not exist\n");
        return -1;
    }
    
    if (!is_directory(parent_inode)) {
        printf("Error: Parent is not a directory\n");
        return -1;
    }
    
    if (!check_permission(parent_inode, EXT2_S_IWUSR)) {
        printf("Error: Permission denied\n");
        return -1;
    }
    
    // 创建文件inode
    uint32_t file_inode = create_inode(EXT2_S_IFREG | 0644, get_current_uid(), get_current_gid());
    if (file_inode == 0) {
        printf("Error: Failed to create file\n");
        return -1;
    }
    
    // 在父目录中添加目录项
    if (add_directory_entry(parent_inode, child_name, file_inode, 1) != 0) {
        delete_inode(file_inode);
        printf("Error: Failed to add directory entry\n");
        return -1;
    }
    
    printf("File created: %s\n", path);
    return 0;
}

int cmd_delete(const char *path) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    uint32_t inode_no;
    if (path_to_inode(path, &inode_no) != 0) {
        printf("Error: File not found\n");
        return -1;
    }
    
    if (is_directory(inode_no)) {
        printf("Error: Cannot delete directory with delete command\n");
        return -1;
    }
    
    if (!check_permission(inode_no, EXT2_S_IWUSR)) {
        printf("Error: Permission denied\n");
        return -1;
    }
    
    // 获取父目录
    uint32_t parent_inode;
    char child_name[MAX_FILENAME];
    if (get_parent_inode(path, &parent_inode, child_name) != 0) {
        printf("Error: Invalid path\n");
        return -1;
    }
    
    // 从父目录中删除目录项
    if (remove_directory_entry(parent_inode, child_name) != 0) {
        printf("Error: Failed to remove directory entry\n");
        return -1;
    }
    
    // 删除文件inode
    if (delete_inode(inode_no) != 0) {
        printf("Error: Failed to delete file\n");
        return -1;
    }
    
    printf("File deleted: %s\n", path);
    return 0;
}

int cmd_open(const char *path, int flags) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    uint32_t inode_no;
    if (path_to_inode(path, &inode_no) != 0) {
        printf("Error: File not found\n");
        return -1;
    }
    
    if (!is_regular_file(inode_no)) {
        printf("Error: Not a regular file\n");
        return -1;
    }
    
    // 检查权限
    int access = 0;
    if (flags & O_RDONLY) access |= EXT2_S_IRUSR;
    if (flags & O_WRONLY) access |= EXT2_S_IWUSR;
    if (flags & O_RDWR) access |= (EXT2_S_IRUSR | EXT2_S_IWUSR);
    
    if (!check_permission(inode_no, access)) {
        printf("Error: Permission denied\n");
        return -1;
    }
    
    // 查找空闲文件描述符
    int fd = -1;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (!fs.open_files[i].is_open) {
            fd = i;
            break;
        }
    }
    
    if (fd == -1) {
        printf("Error: Too many open files\n");
        return -1;
    }
    
    // 打开文件
    fs.open_files[fd].fd = fs.next_fd++;
    fs.open_files[fd].inode_no = inode_no;
    fs.open_files[fd].flags = flags;
    fs.open_files[fd].offset = 0;
    fs.open_files[fd].is_open = 1;
    
    printf("File opened: %s (fd=%d)\n", path, fs.open_files[fd].fd);
    return fs.open_files[fd].fd;
}

int cmd_close(int fd) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    // 查找文件描述符
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (fs.open_files[i].is_open && fs.open_files[i].fd == fd) {
            fs.open_files[i].is_open = 0;
            printf("File closed: fd=%d\n", fd);
            return 0;
        }
    }
    
    printf("Error: Invalid file descriptor\n");
    return -1;
}

int cmd_read(int fd, void *buffer, size_t size) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    // 查找文件描述符
    open_file_t *file = NULL;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (fs.open_files[i].is_open && fs.open_files[i].fd == fd) {
            file = &fs.open_files[i];
            break;
        }
    }
    
    if (file == NULL) {
        printf("Error: Invalid file descriptor\n");
        return -1;
    }
    
    if (!(file->flags & O_RDONLY) && !(file->flags & O_RDWR)) {
        printf("Error: File not opened for reading\n");
        return -1;
    }
    
    ssize_t bytes_read = read_inode_data(file->inode_no, buffer, size, file->offset);
    if (bytes_read > 0) {
        file->offset += bytes_read;
    }
    
    return bytes_read;
}

int cmd_write(int fd, const void *buffer, size_t size) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    // 查找文件描述符
    open_file_t *file = NULL;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (fs.open_files[i].is_open && fs.open_files[i].fd == fd) {
            file = &fs.open_files[i];
            break;
        }
    }
    
    if (file == NULL) {
        printf("Error: Invalid file descriptor\n");
        return -1;
    }
    
    if (!(file->flags & O_WRONLY) && !(file->flags & O_RDWR)) {
        printf("Error: File not opened for writing\n");
        return -1;
    }
    
    ssize_t bytes_written = write_inode_data(file->inode_no, buffer, size, file->offset);
    if (bytes_written > 0) {
        file->offset += bytes_written;
    }
    
    return bytes_written;
}

// 目录操作命令
int cmd_dir(const char *path) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    return list_directory(path);
}

int cmd_mkdir(const char *path) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    int result = create_directory(path, 0755);
    if (result == 0) {
        printf("Directory created: %s\n", path);
    } else {
        printf("Error: Failed to create directory\n");
    }
    return result;
}

int cmd_rmdir(const char *path) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    int result = delete_directory(path);
    if (result == 0) {
        printf("Directory removed: %s\n", path);
    } else {
        printf("Error: Failed to remove directory\n");
    }
    return result;
}

int cmd_cd(const char *path) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    int result = change_directory(path);
    if (result == 0) {
        printf("Changed directory to: %s\n", path);
    } else {
        printf("Error: Failed to change directory\n");
    }
    return result;
}

// 用户操作命令
int cmd_login(const char *username, const char *password) {
    int result = login(username, password);
    if (result != 0) {
        printf("Error: Login failed\n");
    }
    return result;
}

int cmd_logout(void) {
    logout();
    return 0;
}

int cmd_users(void) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    list_users();
    return 0;
}

// 文件系统管理命令
int cmd_format(const char *disk_image) {
    printf("Formatting disk image: %s\n", disk_image);
    
    // 创建磁盘镜像文件
    FILE *fp = fopen(disk_image, "wb");
    if (fp == NULL) {
        printf("Error: Cannot create disk image\n");
        return -1;
    }
    
    // 写入空块
    uint8_t zero_block[BLOCK_SIZE] = {0};
    for (int i = 0; i < MAX_BLOCKS; i++) {
        fwrite(zero_block, 1, BLOCK_SIZE, fp);
    }
    
    fclose(fp);
    
    // 初始化超级块
    ext2_superblock_t superblock;
    memset(&superblock, 0, sizeof(superblock));
    
    superblock.s_inodes_count = MAX_INODES;
    superblock.s_blocks_count = MAX_BLOCKS;
    superblock.s_r_blocks_count = 10;
    superblock.s_free_blocks_count = MAX_BLOCKS - 10;
    superblock.s_free_inodes_count = MAX_INODES - 1;
    superblock.s_first_data_block = 1;
    superblock.s_log_block_size = 0;
    superblock.s_log_frag_size = 0;
    superblock.s_blocks_per_group = MAX_BLOCKS;
    superblock.s_frags_per_group = MAX_BLOCKS;
    superblock.s_inodes_per_group = MAX_INODES;
    superblock.s_mtime = time(NULL);
    superblock.s_wtime = time(NULL);
    superblock.s_mnt_count = 0;
    superblock.s_max_mnt_count = 20;
    superblock.s_magic = 0xEF53;
    superblock.s_state = 1;
    superblock.s_errors = 1;
    superblock.s_minor_rev_level = 0;
    superblock.s_lastcheck = time(NULL);
    superblock.s_checkinterval = 1800;
    superblock.s_creator_os = 0;
    superblock.s_rev_level = 0;
    superblock.s_def_resuid = 0;
    superblock.s_def_resgid = 0;
    superblock.s_first_ino = 11;
    superblock.s_inode_size = sizeof(ext2_inode_t);
    superblock.s_block_group_nr = 0;
    superblock.s_feature_compat = 0;
    superblock.s_feature_incompat = 0;
    superblock.s_feature_ro_compat = 0;
    
    // 写入超级块
    FILE *fp2 = fopen(disk_image, "r+b");
    if (fp2 == NULL) {
        printf("Error: Cannot write superblock\n");
        return -1;
    }
    
    fwrite(&superblock, 1, sizeof(superblock), fp2);
    fclose(fp2);
    
    printf("Disk image formatted successfully\n");
    return 0;
}

int cmd_mount(const char *disk_image) {
    if (init_disk_image(disk_image) != 0) {
        printf("Error: Failed to mount disk image\n");
        return -1;
    }
    
    // 读取超级块
    if (read_block(0, &fs.superblock) != 0) {
        printf("Error: Failed to read superblock\n");
        close_disk_image();
        return -1;
    }
    
    // 验证魔数
    if (fs.superblock.s_magic != 0xEF53) {
        printf("Error: Invalid file system magic number\n");
        close_disk_image();
        return -1;
    }
    
    strncpy(fs.disk_image, disk_image, sizeof(fs.disk_image) - 1);
    fs.disk_image[sizeof(fs.disk_image) - 1] = '\0';
    
    printf("Disk image mounted: %s\n", disk_image);
    return 0;
}

int cmd_umount(void) {
    close_disk_image();
    printf("Disk image unmounted\n");
    return 0;
}

int cmd_status(void) {
    printf("File System Status:\n");
    printf("Disk image: %s\n", fs.disk_image);
    printf("Total blocks: %u\n", fs.superblock.s_blocks_count);
    printf("Free blocks: %u\n", fs.superblock.s_free_blocks_count);
    printf("Total inodes: %u\n", fs.superblock.s_inodes_count);
    printf("Free inodes: %u\n", fs.superblock.s_free_inodes_count);
    printf("Current user: %s\n", get_current_username());
    
    int open_count = 0;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (fs.open_files[i].is_open) {
            open_count++;
        }
    }
    printf("Open files: %d\n", open_count);
    
    return 0;
}

// 权限管理命令
int cmd_chmod(const char *path, uint16_t mode) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    uint32_t inode_no;
    if (path_to_inode(path, &inode_no) != 0) {
        printf("Error: File not found\n");
        return -1;
    }
    
    int result = change_permission(inode_no, mode);
    if (result == 0) {
        printf("Permissions changed: %s\n", path);
    } else {
        printf("Error: Failed to change permissions\n");
    }
    return result;
}

int cmd_chown(const char *path, uint16_t uid, uint16_t gid) {
    if (!is_logged_in()) {
        printf("Error: Not logged in\n");
        return -1;
    }
    
    uint32_t inode_no;
    if (path_to_inode(path, &inode_no) != 0) {
        printf("Error: File not found\n");
        return -1;
    }
    
    int result = change_owner(inode_no, uid, gid);
    if (result == 0) {
        printf("Owner changed: %s\n", path);
    } else {
        printf("Error: Failed to change owner\n");
    }
    return result;
}

// 帮助命令
void cmd_help(void) {
    printf("Available commands:\n");
    printf("  format <disk_image>     - Format a new disk image\n");
    printf("  mount <disk_image>      - Mount a disk image\n");
    printf("  umount                  - Unmount current disk image\n");
    printf("  status                  - Show file system status\n");
    printf("  login <user> <pass>     - Login as user\n");
    printf("  logout                  - Logout current user\n");
    printf("  users                   - List all users\n");
    printf("  mkdir <path>            - Create directory\n");
    printf("  rmdir <path>            - Remove directory\n");
    printf("  dir <path>              - List directory contents\n");
    printf("  cd <path>               - Change directory\n");
    printf("  create <path>           - Create file\n");
    printf("  delete <path>           - Delete file\n");
    printf("  open <path> <flags>     - Open file (0=read, 1=write, 2=readwrite)\n");
    printf("  close <fd>              - Close file\n");
    printf("  read <fd> <size>        - Read from file\n");
    printf("  write <fd> <data>       - Write to file\n");
    printf("  chmod <path> <mode>     - Change file permissions\n");
    printf("  chown <path> <uid> <gid> - Change file owner\n");
    printf("  help                    - Show this help\n");
    printf("  quit                    - Exit program\n");
}

void print_usage(void) {
    printf("EXT2 File System Simulator\n");
    printf("Usage: ./ext2fs\n");
    printf("Type 'help' for available commands\n");
}

// 命令解析
int parse_command(char *line) {
    char *token = strtok(line, " \t\n");
    if (token == NULL) {
        return 0;
    }
    
    if (strcmp(token, "format") == 0) {
        char *disk_image = strtok(NULL, " \t\n");
        if (disk_image == NULL) {
            printf("Error: Missing disk image name\n");
            return -1;
        }
        return cmd_format(disk_image);
    }
    else if (strcmp(token, "mount") == 0) {
        char *disk_image = strtok(NULL, " \t\n");
        if (disk_image == NULL) {
            printf("Error: Missing disk image name\n");
            return -1;
        }
        return cmd_mount(disk_image);
    }
    else if (strcmp(token, "umount") == 0) {
        return cmd_umount();
    }
    else if (strcmp(token, "status") == 0) {
        return cmd_status();
    }
    else if (strcmp(token, "login") == 0) {
        char *username = strtok(NULL, " \t\n");
        char *password = strtok(NULL, " \t\n");
        if (username == NULL || password == NULL) {
            printf("Error: Missing username or password\n");
            return -1;
        }
        return cmd_login(username, password);
    }
    else if (strcmp(token, "logout") == 0) {
        return cmd_logout();
    }
    else if (strcmp(token, "users") == 0) {
        return cmd_users();
    }
    else if (strcmp(token, "mkdir") == 0) {
        char *path = strtok(NULL, " \t\n");
        if (path == NULL) {
            printf("Error: Missing directory path\n");
            return -1;
        }
        return cmd_mkdir(path);
    }
    else if (strcmp(token, "rmdir") == 0) {
        char *path = strtok(NULL, " \t\n");
        if (path == NULL) {
            printf("Error: Missing directory path\n");
            return -1;
        }
        return cmd_rmdir(path);
    }
    else if (strcmp(token, "dir") == 0) {
        char *path = strtok(NULL, " \t\n");
        if (path == NULL) {
            path = "/";
        }
        return cmd_dir(path);
    }
    else if (strcmp(token, "cd") == 0) {
        char *path = strtok(NULL, " \t\n");
        if (path == NULL) {
            path = "/";
        }
        return cmd_cd(path);
    }
    else if (strcmp(token, "create") == 0) {
        char *path = strtok(NULL, " \t\n");
        if (path == NULL) {
            printf("Error: Missing file path\n");
            return -1;
        }
        return cmd_create(path);
    }
    else if (strcmp(token, "delete") == 0) {
        char *path = strtok(NULL, " \t\n");
        if (path == NULL) {
            printf("Error: Missing file path\n");
            return -1;
        }
        return cmd_delete(path);
    }
    else if (strcmp(token, "open") == 0) {
        char *path = strtok(NULL, " \t\n");
        char *flags_str = strtok(NULL, " \t\n");
        if (path == NULL || flags_str == NULL) {
            printf("Error: Missing file path or flags\n");
            return -1;
        }
        int flags = atoi(flags_str);
        return cmd_open(path, flags);
    }
    else if (strcmp(token, "close") == 0) {
        char *fd_str = strtok(NULL, " \t\n");
        if (fd_str == NULL) {
            printf("Error: Missing file descriptor\n");
            return -1;
        }
        int fd = atoi(fd_str);
        return cmd_close(fd);
    }
    else if (strcmp(token, "read") == 0) {
        char *fd_str = strtok(NULL, " \t\n");
        char *size_str = strtok(NULL, " \t\n");
        if (fd_str == NULL || size_str == NULL) {
            printf("Error: Missing file descriptor or size\n");
            return -1;
        }
        int fd = atoi(fd_str);
        size_t size = atoi(size_str);
        char buffer[1024];
        int result = cmd_read(fd, buffer, size);
        if (result > 0) {
            buffer[result] = '\0';
            printf("Read: %s\n", buffer);
        }
        return result;
    }
    else if (strcmp(token, "write") == 0) {
        char *fd_str = strtok(NULL, " \t\n");
        char *data = strtok(NULL, "\n");
        if (fd_str == NULL || data == NULL) {
            printf("Error: Missing file descriptor or data\n");
            return -1;
        }
        int fd = atoi(fd_str);
        return cmd_write(fd, data, strlen(data));
    }
    else if (strcmp(token, "chmod") == 0) {
        char *path = strtok(NULL, " \t\n");
        char *mode_str = strtok(NULL, " \t\n");
        if (path == NULL || mode_str == NULL) {
            printf("Error: Missing path or mode\n");
            return -1;
        }
        uint16_t mode = strtol(mode_str, NULL, 8);
        return cmd_chmod(path, mode);
    }
    else if (strcmp(token, "chown") == 0) {
        char *path = strtok(NULL, " \t\n");
        char *uid_str = strtok(NULL, " \t\n");
        char *gid_str = strtok(NULL, " \t\n");
        if (path == NULL || uid_str == NULL || gid_str == NULL) {
            printf("Error: Missing path, uid, or gid\n");
            return -1;
        }
        uint16_t uid = atoi(uid_str);
        uint16_t gid = atoi(gid_str);
        return cmd_chown(path, uid, gid);
    }
    else if (strcmp(token, "help") == 0) {
        cmd_help();
        return 0;
    }
    else if (strcmp(token, "quit") == 0 || strcmp(token, "exit") == 0) {
        return 1; // 退出标志
    }
    else {
        printf("Unknown command: %s\n", token);
        printf("Type 'help' for available commands\n");
        return -1;
    }
}

void command_loop(void) {
    char line[1024];
    
    printf("EXT2 File System Simulator\n");
    printf("Type 'help' for available commands\n");
    
    while (1) {
        printf("ext2fs> ");
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }
        
        int result = parse_command(line);
        if (result == 1) {
            break; // 退出
        }
    }
} 