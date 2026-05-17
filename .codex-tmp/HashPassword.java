import org.springframework.security.crypto.bcrypt.BCrypt;

public class HashPassword {
    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected a single password argument");
        }
        System.out.println(BCrypt.hashpw(args[0], BCrypt.gensalt(10)));
    }
}
