package pro.akosarev.sandbox;

import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.CumulativePermission;
import org.springframework.security.acls.model.Permission;

// Стандартных разрешений нам не хватает, нам нужно разрешение на переворачивание стола (╯°□°)╯︵ ┻━┻
public class FlipTablePermission extends BasePermission {

    public static final Permission FT_1 = new FlipTablePermission(1 << 31, '(');

    public static final Permission FT_2 = new FlipTablePermission(1 << 30, '╯');

    public static final Permission FT_3 = new FlipTablePermission(1 << 29, '°');

    public static final Permission FT_4 = new FlipTablePermission(1 << 28, '□');

    public static final Permission FT_5 = new FlipTablePermission(1 << 27, '°');

    public static final Permission FT_6 = new FlipTablePermission(1 << 26, ')');

    public static final Permission FT_7 = new FlipTablePermission(1 << 25, '╯');

    public static final Permission FT_8 = new FlipTablePermission(1 << 24, '︵');

    public static final Permission FT_9 = new FlipTablePermission(1 << 23, ' ');

    public static final Permission FT_10 = new FlipTablePermission(1 << 22, '┻');

    public static final Permission FT_11 = new FlipTablePermission(1 << 21, '━');

    public static final Permission FT_12 = new FlipTablePermission(1 << 20, '┻');

    // (╯°□°)╯︵ ┻━┻....................
    public static final Permission FLIP_TABLE = new CumulativePermission()
            .set(FT_1)
            .set(FT_2)
            .set(FT_3)
            .set(FT_4)
            .set(FT_5)
            .set(FT_6)
            .set(FT_7)
            .set(FT_8)
            .set(FT_8)
            .set(FT_9)
            .set(FT_10)
            .set(FT_11)
            .set(FT_12);

    protected FlipTablePermission(int mask) {
        super(mask);
    }

    public FlipTablePermission(int mask, char code) {
        super(mask, code);
    }
}