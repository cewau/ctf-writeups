#include <SoftwareSerial.h>
#include <LiquidCrystal_I2C.h>






#define I2C_ADDR    0x26
#define LCD_COLUMNS 16
#define LCD_LINES   2

#define RX_PIN      11
#define TX_PIN      12

LiquidCrystal_I2C lcd(I2C_ADDR, LCD_COLUMNS, LCD_LINES);
LiquidCrystal_I2C lcd2(0x26, LCD_COLUMNS, LCD_LINES);

SoftwareSerial uartSerial(RX_PIN, TX_PIN);

void setup() {
  // put your setup code here, to run once:
  // Serial.begin(115200);
  uartSerial.begin(9600);
  uartSerial.print("F8g3a_9V7G2$d#0h");

  lcd.init();
  lcd2.init();
  lcd.backlight();
  lcd2.backlight();
  lcd2.setCursor(0, 0);
  lcd.println("Hello World! aaaaaa");
  lcd.setCursor(0, 1);
  lcd.print("test");
  lcd.print("hi");
  lcd.print("test");
  lcd.print("hi");
  lcd.print("test");
  lcd.print("hi");
  // delay(1000);
  // lcd.clear
  // lcd.setCursor(0, 0);
  // lcd.print("test");
}

void loop() {
  // put your main code here, to run repeatedly:
  lcd2.print("hi");
  lcd.print("Read key chip:");
  lcd.setCursor(0, 1);
  
  while (uartSerial.available()) {
    lcd.print((char)uartSerial.read());
  }
  delay(10000);

}
