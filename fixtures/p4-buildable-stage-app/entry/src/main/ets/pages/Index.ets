@Entry
@Component
struct Index {
  build() {
    Column() {
      Text('鸿鉴 HCheck P4 构建样例')
        .fontSize(24)
        .fontWeight(FontWeight.Bold)
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
  }
}
