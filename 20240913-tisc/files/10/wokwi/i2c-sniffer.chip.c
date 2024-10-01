// Wokwi Custom Chip - For docs and examples see:
// https://docs.wokwi.com/chips-api/getting-started
//
// SPDX-License-Identifier: MIT
// Copyright 2023 

#include "wokwi-api.h"
#include <stdio.h>
#include <stdlib.h>

const int ADDRESS = 0x68;

typedef struct {
  uint8_t dummy;
} chip_state_t;

static bool on_i2c_connect(void *user_data, uint32_t address, bool connect);
static uint8_t on_i2c_read(void *user_data);
static bool on_i2c_write(void *user_data, uint8_t data);

void chip_init() {
  chip_state_t *chip = malloc(sizeof(chip_state_t));

  chip->dummy = 0;

  const i2c_config_t i2c_config = {
    .user_data = chip,
    .address = ADDRESS,
    .scl = pin_init("SCL", INPUT),
    .sda = pin_init("SDA", INPUT),
    .connect = on_i2c_connect,
    .read = on_i2c_read,
    .write = on_i2c_write,
  };
  i2c_init(&i2c_config);
}

bool on_i2c_connect(void *user_data, uint32_t address, bool connect) {
  return true;
}

uint8_t on_i2c_read(void *user_data) {
  return 0;
}

bool on_i2c_write(void *user_data, uint8_t data) {
  printf("%c", (char) data);
  if ((char) data == '}') {
    printf("\n");
  }
  return false;
}
