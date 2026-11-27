public class TetragonJavaDemo {
    public static void main(String[] args) throws InterruptedException {
        TetragonJavaDemo demo = new TetragonJavaDemo();
        while (true) {
            demo.work(System.nanoTime());
            Thread.sleep(500);
        }
    }

    public int work(long value) {
        switch ((int) (value & 3)) {
        case 0:
            return 10;
        case 1:
            return 20;
        default:
            return 30;
        }
    }
}
