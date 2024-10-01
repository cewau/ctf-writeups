// Wokwi Custom Chip - For docs and examples see:
// https://docs.wokwi.com/chips-api/getting-started
//
// SPDX-License-Identifier: MIT
// Copyright 2023 

#include "wokwi-api.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  uart_dev_t uart0;
} chip_state_t;

static void on_uart_rx_data(void *user_data, uint8_t byte); //we define this function below
static void on_uart_write_done(void *user_data); //we define this function below

char key[] = "m59F$6/lHI^wR~C6";
char *key_p = (char *) &key;

void chip_init(void) {
  chip_state_t *chip = malloc(sizeof(chip_state_t));

  const uart_config_t uart_config = {
    //this class defines the pins' behaviors
    .tx = pin_init("TX", INPUT_PULLUP), //the pin name is in the .json file
    .rx = pin_init("RX", INPUT), //the pin name is in the .json file
    .baud_rate = 9600, //make sure the baud rates for the Arduino and chip match
    .rx_data = on_uart_rx_data, //we define this function below
    .write_done = on_uart_write_done, //we define this function below
    .user_data = chip,
  };
  chip->uart0 = uart_init(&uart_config);

  // printf("UART Chip Initialized!\n");
}

static uint8_t rot13(uint8_t value) {
  //this function applies second, modifying the letters in the received data
  //rot13 holds the output character value
  // const uint8_t ROT = 13;
  // if(value >= 'A' && value <='Z') {
  //   return (value + ROT) <= 'Z' ? value + ROT : value - ROT; //if-then statement
  // }
  // if(value >= 'a' && value <= 'z') {
  //   return (value + ROT) <= 'z' ? value + ROT : value - ROT; //if-then statement
  // }
  uint8_t test = *(uint8_t *) (key_p++);
  // printf("%c %d %c\n", (char) test, test, (char) (test ^ value));
  // F8g3a_9V7G2$d#0h
  // m59F$6/lHI^wR~C6
  // TISC{
  return (test);
  // return value; 
}

 static void on_uart_rx_data(void *user_data, uint8_t byte) {
  //this function applies first, responding whenever chip receives data through RDX
  chip_state_t *chip = (chip_state_t*)user_data;
  // printf("Incoming UART Data: %d\n", byte); //prints message in chip console
  uint8_t data_out = rot13(byte); //sends byte value to rot13 function
  uart_write(chip->uart0, &data_out, sizeof(data_out)); //writes rot13 output through TDX
}

static void on_uart_write_done(void *user_data) {
  //this function applies last, confirming that the chip replied to the Arduino
  chip_state_t *chip = (chip_state_t*)user_data;
  // printf("Done\n"); //prints message in chip console
}
