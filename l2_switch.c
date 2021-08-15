#include "l2_switch.h"
#include "mac_table.h"

#define L2FWD_MAX_PORTS 32


static uint16_t dev_id_list[L2FWD_MAX_PORTS] = {};

static __inline__ int _br_mac_hash(uint8_t *mac)
{
	unsigned long x;

	x = mac[0];
	x = (x << 2) ^ mac[1];
	x = (x << 2) ^ mac[2];
	x = (x << 2) ^ mac[3];
	x = (x << 2) ^ mac[4];
	x = (x << 2) ^ mac[5];

	x ^= x >> 8;

	//return x & (BR_HASH_SIZE - 1);
	return x;
}


static unsigned br_mac_hash (__attribute__((unused))hash_function * f, unsigned char * d, __attribute__((unused))size_t n)
{
	int index = _br_mac_hash((uint8_t *)d);
	return index;
}
	

/* 功能：初始化mac表
 * */
hash_table_t*
mac_map_create(void)
{
	int i;

	for (i = 0; i < L2FWD_MAX_PORTS; i++)
		dev_id_list[i] = i;


	hash_table_t* mac_map;
	mac_map = hash_new(BR_HASH_SIZE, 6, 0,0);
	if(!mac_map)
		return NULL;

	//设置hash函数
	hash_function *hash_func = hash_get_hashfun(mac_map);
	hashfunc_set_keyops(hash_func, br_mac_hash, NULL);
	return mac_map;
}	

void 
mac_map_destroy(hash_table_t* mac_map)
{
	hash_destory_all(mac_map, NULL);
}



/* 功能：根据mac，查找其网卡id号
 * mac: 源码mac地址
 * return: -1 错误
 * */
int mac_to_net_id(hash_table_t *mac_map, uint8_t *mac)
{
	uint16_t *dev_id = NULL;
	
	dev_id = hash_find(mac_map, mac, NULL);
	if (!dev_id)
		return -1;
	else
		return (*dev_id);
}	

/* 功能：mac自学习
 * mac: MAC地址
 * dev_id: 目的网口
 * */
void mac_self_learn(hash_table_t *mac_map, uint8_t *mac, uint16_t dev_id)
{
	if (dev_id >= L2FWD_MAX_PORTS)
		return;
	hash_add(mac_map, mac, &dev_id_list[dev_id], AGE_TIME, 0, NULL, NULL);
}

/* 功能：hash表清理
 * */
void clean_mac_map(hash_table_t *mac_map)
{
	hash_reomve_expired(mac_map, NULL);
}

