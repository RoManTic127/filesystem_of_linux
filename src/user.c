#include "../include/user.h"
#include "../include/ext2.h"
#include "../include/disk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>

// 全局变量
extern ext2_fs_t fs;

// 用户管理
int init_users(void) {
    memset(fs.users, 0, sizeof(fs.users));
    fs.current_user = -1;
    
    // 创建默认用户
    add_user("root", "root", 0, 0);
    add_user("user1", "password1", 1, 1);
    add_user("user2", "password2", 2, 1);
    
    return 0;
}

int add_user(const char *username, const char *password, uint16_t uid, uint16_t gid) {
    if (!username || !password) return -3; // 参数无效

    // 检查UID/GID冲突
    for (int i = 0; i < MAX_USERS; i++) {
        if (fs.users[i].is_active && 
           (fs.users[i].uid == uid || fs.users[i].gid == gid)) {
            return -2; // UID/GID冲突
        }
    }
    
    for (int i = 0; i < MAX_USERS; i++) {
        if (!fs.users[i].is_active) {
            strncpy(fs.users[i].username, username, sizeof(fs.users[i].username) - 1);
            fs.users[i].username[sizeof(fs.users[i].username) - 1] = '\0';
            
            // 简单的密码加密（实际应用中应使用更安全的方法）
            strncpy(fs.users[i].password, password, sizeof(fs.users[i].password) - 1);
            fs.users[i].password[sizeof(fs.users[i].password) - 1] = '\0';
            
            fs.users[i].uid = uid;
            fs.users[i].gid = gid;
            fs.users[i].is_active = 1;
            
            return 0;//找到就返回
        }
    }
    
    return -1; // 用户表已满
}

int remove_user(const char *username) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (fs.users[i].is_active && strcmp(fs.users[i].username, username) == 0) {
            fs.users[i].is_active = 0;
            return 0;
        }
    }
    
    return -1; // 用户不存在
}

int find_user(const char *username) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (fs.users[i].is_active && strcmp(fs.users[i].username, username) == 0) {
            return i;
        }
    }
    
    return -1; // 用户不存在
}

// 用户认证
int login(const char *username, const char *password) {
    int user_index = find_user(username);
    if (user_index == -1) {
        return -1; // 用户不存在
    }
    
    // 简单的密码验证（实际应用中应使用加密）
    if (strcmp(fs.users[user_index].password, password) == 0) {
        fs.current_user = user_index;
        printf("Login successful. Welcome, %s!\n", username);
        return 0;
    }
    
    return -1; // 密码错误
}

void logout(void) {
    if (fs.current_user != -1) {
        printf("Logout successful. Goodbye, %s!\n", fs.users[fs.current_user].username);
        fs.current_user = -1;
    }
}

int is_logged_in(void) {
    return fs.current_user != -1;
}

// 权限检查
int check_file_permission(uint32_t inode_no, int access) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return 0;
    }
    
    uint16_t uid = get_current_uid();
    uint16_t gid = get_current_gid();
    
    // root用户有所有权限
    if (uid == 0) {
        return 1;
    }
    
    uint16_t mode = 0;
    if (uid == inode.i_uid) {
        mode = (inode.i_mode >> 6) & 0x7;
    } else if (gid == inode.i_gid) {
        mode = (inode.i_mode >> 3) & 0x7;
    } else {
        mode = inode.i_mode & 0x7;
    }
    
    return (mode & access) == access;
}

int check_directory_permission(uint32_t inode_no, int access) {
    return check_file_permission(inode_no, access);
}

// 当前用户信息
uint16_t get_current_uid(void) {
    if (fs.current_user == -1) {
        return 65535; // 无效用户ID
    }
    return fs.users[fs.current_user].uid;
}

uint16_t get_current_gid(void) {
    if (fs.current_user == -1) {
        return 65535; // 无效组ID
    }
    return fs.users[fs.current_user].gid;
}

const char* get_current_username(void) {
    if (fs.current_user == -1) {
        return "anonymous";
    }
    return fs.users[fs.current_user].username;
}

// 用户列表
void list_users(void) {
    printf("User List:\n");
    printf("%-15s %-10s %-10s %-10s\n", "Username", "UID", "GID", "Status");
    printf("----------------------------------------\n");
    
    for (int i = 0; i < MAX_USERS; i++) {
        if (fs.users[i].is_active) {
            const char *status = (i == fs.current_user) ? "Logged in" : "Active";
            printf("%-15s %-10u %-10u %-10s\n", 
                   fs.users[i].username, 
                   fs.users[i].uid, 
                   fs.users[i].gid, 
                   status);
        }
    }
}

// 密码管理
int change_password(const char *username, const char *old_password, const char *new_password) {
    int user_index = find_user(username);
    if (user_index == -1) {
        return -1; // 用户不存在
    }
    
    // 验证旧密码
    if (strcmp(fs.users[user_index].password, old_password) != 0) {
        return -1; // 旧密码错误
    }
    
    // 更新密码
    strncpy(fs.users[user_index].password, new_password, sizeof(fs.users[user_index].password) - 1);
    fs.users[user_index].password[sizeof(fs.users[user_index].password) - 1] = '\0';
    
    return 0;
} 