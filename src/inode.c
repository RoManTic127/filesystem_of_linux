#include "../include/inode.h"
#include "../include/disk.h"
#include "../include/ext2.h"
#include "../include/user.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

// Inode操作
int create_inode(uint16_t mode, uint16_t uid, uint16_t gid) {
    uint32_t inode_no = allocate_inode();
    if (inode_no == 0) {
        return -1;
    }
    
    ext2_inode_t inode;
    memset(&inode, 0, sizeof(ext2_inode_t));
    
    inode.i_mode = mode;
    inode.i_uid = uid;
    inode.i_gid = gid;
    inode.i_size = 0;
    inode.i_links_count = 1;
    inode.i_blocks = 0;
    inode.i_atime = time(NULL);
    inode.i_ctime = time(NULL);
    inode.i_mtime = time(NULL);
    
    // 初始化块指针数组
    for (int i = 0; i < 15; i++) {
        inode.i_block[i] = 0;
    }
    
    if (write_inode(inode_no, &inode) != 0) {
        free_inode(inode_no);
        return -1;
    }
    
    return inode_no;
}

int delete_inode(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    // 释放所有数据块
    for (int i = 0; i < 12; i++) {
        if (inode.i_block[i] != 0) {
            free_block(inode.i_block[i]);
        }
    }
    
    // 释放间接块（简化实现，只处理一级间接）
    if (inode.i_block[12] != 0) {
        uint32_t indirect_blocks[BLOCK_SIZE / 4];
        if (read_block(inode.i_block[12], indirect_blocks) == 0) {
            for (int i = 0; i < BLOCK_SIZE / 4; i++) {
                if (indirect_blocks[i] != 0) {
                    free_block(indirect_blocks[i]);
                }
            }
        }
        free_block(inode.i_block[12]);
    }
    
    // 清除inode
    memset(&inode, 0, sizeof(ext2_inode_t));
    write_inode(inode_no, &inode);
    
    // 释放inode
    free_inode(inode_no);
    
    return 0;
}

int get_inode_block(uint32_t inode_no, uint32_t block_index, uint32_t *block_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    if (block_index < 12) {
        *block_no = inode.i_block[block_index];
        return 0;
    } else if (block_index < 12 + BLOCK_SIZE / 4) {
        // 一级间接块
        if (inode.i_block[12] == 0) {
            *block_no = 0;
            return 0;
        }
        
        uint32_t indirect_blocks[BLOCK_SIZE / 4];
        if (read_block(inode.i_block[12], indirect_blocks) != 0) {
            return -1;
        }
        
        *block_no = indirect_blocks[block_index - 12];
        return 0;
    }
    
    return -1; // 超出范围
}

int set_inode_block(uint32_t inode_no, uint32_t block_index, uint32_t block_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    if (block_index < 12) {
        inode.i_block[block_index] = block_no;
    } else if (block_index < 12 + BLOCK_SIZE / 4) {
        // 一级间接块
        if (inode.i_block[12] == 0) {
            inode.i_block[12] = allocate_block();
            if (inode.i_block[12] == 0) {
                return -1;
            }
        }
        
        uint32_t indirect_blocks[BLOCK_SIZE / 4];
        if (read_block(inode.i_block[12], indirect_blocks) != 0) {
            memset(indirect_blocks, 0, BLOCK_SIZE);
        }
        
        indirect_blocks[block_index - 12] = block_no;
        write_block(inode.i_block[12], indirect_blocks);
    } else {
        return -1; // 超出范围
    }
    
    return write_inode(inode_no, &inode);
}

// 文件读写操作
ssize_t read_inode_data(uint32_t inode_no, void *buffer, size_t size, off_t offset) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    if (offset >= inode.i_size) {
        return 0;
    }
    
    size_t bytes_read = 0;
    size_t remaining = size;
    off_t current_offset = offset;
    
    while (remaining > 0 && current_offset < inode.i_size) {
        uint32_t block_index = current_offset / BLOCK_SIZE;
        uint32_t block_offset = current_offset % BLOCK_SIZE;
        uint32_t block_no;
        
        if (get_inode_block(inode_no, block_index, &block_no) != 0 || block_no == 0) {
            break;
        }
        
        uint8_t block_buffer[BLOCK_SIZE];
        if (read_block(block_no, block_buffer) != 0) {
            break;
        }
        
        size_t bytes_in_block = BLOCK_SIZE - block_offset;
        if (bytes_in_block > remaining) {
            bytes_in_block = remaining;
        }
        if (current_offset + bytes_in_block > inode.i_size) {
            bytes_in_block = inode.i_size - current_offset;
        }
        
        memcpy((char*)buffer + bytes_read, block_buffer + block_offset, bytes_in_block);
        
        bytes_read += bytes_in_block;
        remaining -= bytes_in_block;
        current_offset += bytes_in_block;
    }
    
    // 更新访问时间
    update_atime(inode_no);
    
    return bytes_read;
}

ssize_t write_inode_data(uint32_t inode_no, const void *buffer, size_t size, off_t offset) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    size_t bytes_written = 0;
    size_t remaining = size;
    off_t current_offset = offset;
    
    while (remaining > 0) {
        uint32_t block_index = current_offset / BLOCK_SIZE;
        uint32_t block_offset = current_offset % BLOCK_SIZE;
        uint32_t block_no;
        
        if (get_inode_block(inode_no, block_index, &block_no) != 0) {
            break;
        }
        
        if (block_no == 0) {
            block_no = allocate_block();
            if (block_no == 0) {
                break;
            }
            if (set_inode_block(inode_no, block_index, block_no) != 0) {
                free_block(block_no);
                break;
            }
        }
        
        uint8_t block_buffer[BLOCK_SIZE];
        if (read_block(block_no, block_buffer) != 0) {
            break;
        }
        
        size_t bytes_in_block = BLOCK_SIZE - block_offset;
        if (bytes_in_block > remaining) {
            bytes_in_block = remaining;
        }
        
        memcpy(block_buffer + block_offset, (char*)buffer + bytes_written, bytes_in_block);
        
        if (write_block(block_no, block_buffer) != 0) {
            break;
        }
        
        bytes_written += bytes_in_block;
        remaining -= bytes_in_block;
        current_offset += bytes_in_block;
    }
    
    // 更新文件大小和时间戳
    if (current_offset > inode.i_size) {
        inode.i_size = current_offset;
        inode.i_blocks = (inode.i_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    }
    
    update_mtime(inode_no);
    update_ctime(inode_no);
    
    return bytes_written;
}

int truncate_inode(uint32_t inode_no, off_t length) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    if (length >= inode.i_size) {
        return 0; // 不需要截断
    }
    
    uint32_t new_blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint32_t old_blocks = (inode.i_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    // 释放多余的块
    for (uint32_t i = new_blocks; i < old_blocks; i++) {
        uint32_t block_no;
        if (get_inode_block(inode_no, i, &block_no) == 0 && block_no != 0) {
            free_block(block_no);
            set_inode_block(inode_no, i, 0);
        }
    }
    
    inode.i_size = length;
    inode.i_blocks = new_blocks;
    
    update_mtime(inode_no);
    update_ctime(inode_no);
    
    return write_inode(inode_no, &inode);
}

// 权限检查
int check_permission(uint32_t inode_no, int access) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return 0;
    }
    
    uint16_t uid = get_current_uid();
    uint16_t gid = get_current_gid();
    
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

int change_permission(uint32_t inode_no, uint16_t mode) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    inode.i_mode = (inode.i_mode & 0xF000) | (mode & 0x0FFF);
    update_ctime(inode_no);
    
    return write_inode(inode_no, &inode);
}

int change_owner(uint32_t inode_no, uint16_t uid, uint16_t gid) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    inode.i_uid = uid;
    inode.i_gid = gid;
    update_ctime(inode_no);
    
    return write_inode(inode_no, &inode);
}

// 时间戳更新
void update_atime(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) == 0) {
        inode.i_atime = time(NULL);
        write_inode(inode_no, &inode);
    }
}

void update_mtime(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) == 0) {
        inode.i_mtime = time(NULL);
        write_inode(inode_no, &inode);
    }
}

void update_ctime(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) == 0) {
        inode.i_ctime = time(NULL);
        write_inode(inode_no, &inode);
    }
}

// 链接计数
int increment_link_count(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    inode.i_links_count++;
    update_ctime(inode_no);
    
    return write_inode(inode_no, &inode);
}

int decrement_link_count(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return -1;
    }
    
    if (inode.i_links_count > 0) {
        inode.i_links_count--;
    }
    update_ctime(inode_no);
    
    return write_inode(inode_no, &inode);
}

// 工具函数
int is_directory(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return 0;
    }
    return (inode.i_mode & 0xF000) == EXT2_S_IFDIR;
}

int is_regular_file(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return 0;
    }
    return (inode.i_mode & 0xF000) == EXT2_S_IFREG;
}

uint32_t get_file_size(uint32_t inode_no) {
    ext2_inode_t inode;
    if (read_inode(inode_no, &inode) != 0) {
        return 0;
    }
    return inode.i_size;
} 