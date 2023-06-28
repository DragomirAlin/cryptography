package ro.dragomiralin;

import java.io.Serializable;

public record SecuredData(String firstName, String lastName) implements Serializable {
}
