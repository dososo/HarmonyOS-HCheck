@Entry
@Component
struct Index {
  build() {
    Column() {
      Text('鸿鉴 HCheck P4 Shared 样例')
        .fontSize(24)
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
  }
}
