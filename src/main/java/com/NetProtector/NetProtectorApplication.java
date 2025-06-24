package com.NetProtector;

import com.NetProtector.Controllers.NetProtectorMainController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

public class NetProtectorApplication extends Application {

    private NetProtectorMainController controller;
    private double xOffset = 0;
    private double yOffset = 0;

    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.initStyle(StageStyle.UNDECORATED);
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/NetProtectorMain.fxml"));
        Scene scene = new Scene(loader.load(), 1380, 720);

        controller = loader.getController();

        String css = getClass().getResource("/css/styles.css").toExternalForm();
        scene.getStylesheets().add(css);
        
        primaryStage.setTitle("NetProtector - Network Security Monitor");
        primaryStage.setScene(scene);

        primaryStage.setResizable(false);
        primaryStage.setFullScreen(true);
        primaryStage.setMaximized(true);
        
        // Enhanced dragging with better performance
        addDragListeners(scene, primaryStage);
        
        primaryStage.setOnCloseRequest(e -> {
            System.out.println("NetProtectorApplication: Close request received.");
            if (controller != null) {
                System.out.println("NetProtectorApplication: Calling controller.shutdown().");
                controller.shutdown();
            }
            System.out.println("NetProtectorApplication: Shutdown process in setOnCloseRequest finished.");
        });
        
        primaryStage.show();
    }
    
    private void addDragListeners(Scene scene, Stage stage) {
        scene.setOnMousePressed((MouseEvent event) -> {
            xOffset = event.getSceneX();
            yOffset = event.getSceneY();
        });
        
        scene.setOnMouseDragged((MouseEvent event) -> {
            stage.setX(event.getScreenX() - xOffset);
            stage.setY(event.getScreenY() - yOffset);
        });
    }

    public static void main(String[] args) {
        launch(args);
    }
}